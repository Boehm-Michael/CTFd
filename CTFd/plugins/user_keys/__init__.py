import os, io, requests, datetime, timedelta
from flask import Blueprint, render_template, request, jsonify, send_file, flash, redirect, url_for
from sqlalchemy import event
from CTFd.models import db, Users
from CTFd.utils.decorators import admins_only, authed_only
from CTFd.utils.user import get_current_user
from CTFd.utils.plugins import override_template

class UserPrivateKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    private_key = db.Column(db.Text)

    def __init__(self, user_id, private_key):
        self.user_id = user_id
        self.private_key = private_key

class UserContainer(db.model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    container_id = db.Column(db.String(128)) # Docker Hash
    container_type = db.Column(db.String(32)) # Either jumpbox or challenge
    expires_at = db.Column(db.DateTime)
    ip_address = db.Column(db.String(64))

    def time_left(self):
        if not self.expires_at:
            return 0
        diff = self.expires_at - datetime.utcnow()
        return max(0, int(diff.total_seconds()))

def load(app):
    app.db.create_all()

    # Template Override to give admin panel and user access to read/modify the private key
    dir_path = os.path.dirname(os.path.realpath(__file__))
    settings_html = os.path.join(dir_path, "templates", "settings.html")
    with open(settings_html, "r") as f:
        override_template("settings.html", f.read())
    
    user_keys_bp = Blueprint("user_keys", __name__, template_folder="templates")

    @user_keys_bp.route("/user/private_key", methods=["GET"])
    @authed_only
    def get_own_key():
        user = get_current_user()
        key_record = UserPrivateKey.query.filter_by(user_id=user.id).first()
        return jsonify({"key": key_record.private_key if key_record else "No key assigned."})
    
    @user_keys_bp.route("/admin/user_keys", methods=["GET", "POST"])
    @admins_only
    def admin_manage_keys():
        if request.method == "POST":
            user_id = request.form.get("user_id")
            key_file = request.files.get("key_file")

            if not user_id or not key_file:
                flash("Missing User ID or File", "danger")
                return redirect(url_for('user_keys.admin_manage_keys'))

            try:
                content = key_file.read().decode('utf-8')
                private_key_content = content.rstrip() + "\n"
                
                if "BEGIN" not in private_key_content:
                    flash("Invalid file: Does not look like a private key.", "warning")
                    return redirect(url_for('user_keys.admin_manage_keys'))

                key_record = UserPrivateKey.query.filter_by(user_id=int(user_id)).first()
                if key_record:
                    key_record.private_key = private_key_content
                else:
                    key_record = UserPrivateKey(user_id=int(user_id), private_key=private_key_content)
                    db.session.add(key_record)
                
                db.session.commit()
                flash(f"Successfully uploaded key for User ID {user_id}", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"Error: {str(e)}", "danger")

        keys = db.session.query(Users, UserPrivateKey).outerjoin(
            UserPrivateKey, Users.id == UserPrivateKey.user_id
        ).all()
        return render_template("admin_keys.html", keys=keys)

    @user_keys_bp.route("/api/v1/user_keys/<user_id>", methods=["POST"])
    @admins_only
    def update_user_key(user_id):
        data = request.get_json()
        new_key = data.get("private_key")
        
        # Check if user exists
        user = Users.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        # Update or Create the key
        key_record = UserPrivateKey.query.filter_by(user_id=user_id).first()
        if key_record:
            key_record.private_key = new_key
        else:
            key_record = UserPrivateKey(user_id=user_id, private_key=new_key)
            db.session.add(key_record)
        
        db.session.commit()
        return jsonify({"success": True})
    
    @user_keys_bp.route("/user/private_key/download", methods=["GET"])
    @authed_only
    def download_private_key():
        user = get_current_user()
        key_record = UserPrivateKey.query.filter_by(user_id=user.id).first()
        
        if not key_record or not key_record.private_key:
            return "No key found", 404

        output_key = key_record.private_key
        if not output_key.endswith("\n"):
            output_key += "\n"

        mem = io.BytesIO()
        mem.write(output_key.encode('utf-8'))
        mem.seek(0)

        return send_file(
            mem,
            as_attachment=True,
            download_name=f"id_rsa_{user.name}",
            mimetype="application/x-pem-file"
        )
    
    @event.listens_for(Users, 'after_insert')
    def notify_machine_on_registration(mapper, connection, target):
        machine_url = "http://172.24.0.1:5000/generate-key" # CHANGE TO ACTUAL IP LATER
        payload = {
            "user_id": target.id,
            "username": target.name
        }
        
        try:
            requests.post(machine_url, json=payload, timeout=2)
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Failed to notify machine: {str(e)}")


    @user_keys_bp.route("/container/spawn", methods=["POST"])
    @authed_only
    def spawn_container():
        user = get_current_user()
        ctype = request.form.get("type", "jumpbox")
        
        # Check if user already has a container of this type
        existing = UserContainer.query.filter_by(user_id=user.id, container_type=ctype).first()
        if existing:
            return jsonify({"success": False, "message": "Container already running."})

        # Notify Manager Script
        manager_url = "http://172.24.0.1:5000/spawn"
        payload = {"user_id": user.id, "type": ctype}
        
        try:
            r = requests.post(manager_url, json=payload, timeout=5)
            data = r.json()
            
            # Save container info to DB
            new_container = UserContainer(
                user_id=user.id,
                container_id=data['id'],
                container_type=ctype,
                ip_address=data['ip'],
                expires_at=datetime.utcnow() + timedelta(hours=2) # 2-hour timer
            )
            db.session.add(new_container)
            db.session.commit()
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    app.db.create_all()
    

    app.register_blueprint(user_keys_bp)