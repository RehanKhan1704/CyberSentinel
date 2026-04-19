import cv2


class QRCodeScanner:

    @staticmethod
    def decode_qr_code(image_path):
        """
        Decode QR code from image path
        """

        try:
            if not image_path:
                return {
                    "success": False,
                    "message": "No image path provided",
                    "data": None
                }

            image = cv2.imread(image_path)

            if image is None:
                return {
                    "success": False,
                    "message": "Invalid image",
                    "data": None
                }

            detector = cv2.QRCodeDetector()
            data, bbox, _ = detector.detectAndDecode(image)

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

    @staticmethod
    def scan_url(data):
        """
        Extract URL from decoded QR data
        """

        if not data:
            return {
                "success": False,
                "message": "No data provided",
                "url": None
            }

        # Direct URL
        if data.startswith(("http://", "https://")):
            url = data

        # Guess URL
        elif "." in data and " " not in data:
            url = f"https://{data}"

        else:
            url = None

        return {
            "success": True,
            "message": "URL processed",
            "url": url
        }
