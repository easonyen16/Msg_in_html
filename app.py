from flask import Flask, jsonify, render_template
import os
import re
from datetime import datetime, timedelta


app = Flask(__name__)

def get_members():
    members = []
    base_path = "./static/data/message/"

    for member_name in os.listdir(base_path):
        member_path = os.path.join(base_path, member_name)
        if os.path.isdir(member_path):
            member = {
                "name": member_name,
                "avatar": f"/static/data/avatar/{member_name}.jpg"
            }
            members.append(member)

    return members

def get_member_messages(member_name):
    base_path = f"./static/data/message/{member_name}/"
    messages = []

    for file_name in sorted(os.listdir(base_path)):
        message = {}
        file_path = os.path.join(base_path, file_name)

        if os.path.isfile(file_path):
            match = re.match(r"(\d+)_(\d+)_(\d+)", file_name)
            if match:
                message_id, message_type, timestamp = match.groups()
            else:
                continue

            # 處理時間戳
            dt = datetime.strptime(timestamp, "%Y%m%d%H%M%S")
            dt = dt + timedelta(hours=9)
            message["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")

            # 根據訊息類型處理訊息內容
            if message_type == "0":
                with open(file_path, "r", encoding="utf-8") as f:
                    message["type"] = "text"
                    message["content"] = f.read()

            elif message_type == "1":
                if file_name.endswith(".txt"):
                    txt_file_path = os.path.join(base_path, f"{message_id}_1_{timestamp}.txt")
                    with open(txt_file_path, "r", encoding="utf-8") as f:
                        message["type"] = "image"
                        message["content"] = f.read()
                    message["image_path"] = os.path.join("/static/data/message", member_name, f"{message_id}_1_{timestamp}.jpg")
                    message["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                elif file_name.endswith(".jpg"):
                    continue

            elif message_type == "3":
                message["type"] = "audio"
                message["audio_path"] = os.path.join("/static/data/message", member_name, file_name)

            elif message_type == "4":
                message["type"] = "video"
                message["video_path"] = os.path.join("/static/data/message", member_name, file_name)

            messages.append(message)
          
    return messages

@app.route('/')
def home():
    members = get_members()
    return render_template('index.html', members=members)

@app.route('/member/<member_name>')
def member(member_name):
    return render_template('member.html', member_name=member_name)

@app.route('/api/member/<member_name>/messages')
def api_get_member_messages(member_name):
    messages = get_member_messages(member_name)
    return jsonify(messages)

if __name__ == '__main__':
    app.run(host='0.0.0.0')

