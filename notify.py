from flask import Flask, request, jsonify
import logging

notify_app = Flask(__name__)

@notify_app.route('/notify', methods=['POST'])
def notify():
    data = request.json
    logging.info(f"Received notification: {data}")
    # Przetwarzaj dane powiadomienia
    return jsonify({"status": "received"}), 200

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        handlers=[
            logging.FileHandler("notify.log"),
            logging.StreamHandler()
        ]
    )
    notify_app.run(port=5001)
