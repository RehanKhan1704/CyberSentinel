import cv2
import numpy as np


class QRCodeScanner:
    def __init__(self):
        self.detector = cv2.QRCodeDetector()

    def scan_qr_code(self, image_path=None, image_bytes=None):
        """
        Scan QR code from an image path or image bytes.
        Keeps same interface as before.
        """

        try:
            # Load image
            if image_path:
                image = cv2.imread(image_path)

            elif image_bytes:
                np_arr = np.frombuffer(image_bytes, np.uint8)
                image = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

            else:
                return {
                    "success": False,
                    "message": "No image provided",
                    "data": None
                }

            if image is None:
                return {
                    "success": False,
                    "message": "Invalid image",
                    "data": None
                }

            # Detect and decode QR
            data, bbox, _ = self.detector.detectAndDecode(image)

            if data:
                return {
                    "success": True,
                    "message": "QR code detected",
                    "data": data
                }
            else:
                return {
                    "success": False,
                    "message": "No QR code found",
                    "data": None
                }

        except Exception as e:
            return {
                "success": False,
                "message": str(e),
                "data": None
            }
