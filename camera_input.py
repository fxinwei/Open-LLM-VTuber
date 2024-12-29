import cv2
import time
from typing import Optional
import numpy as np

class CameraInput:
    """
    Handles camera input capture at regular intervals.
    """
    def __init__(self, interval: int = 10, camera_id: int = 0):
        """
        Initialize camera capture.
        
        Args:
            interval: Time between captures in seconds
            camera_id: Camera device ID
        """
        self.interval = interval
        self.camera_id = camera_id
        self.cap = None
        self.last_capture_time = 0
    
    def initialize(self):
        """Initialize camera capture."""
        if self.cap is None:
            self.cap = cv2.VideoCapture(self.camera_id)
            if not self.cap.isOpened():
                raise RuntimeError("Failed to open camera")
    
    def get_frame(self) -> Optional[np.ndarray]:
        """Capture a frame if interval has elapsed."""
        current_time = time.time()
        for _ in range(5):
            self.cap.read() # clear camera cache

        if current_time - self.last_capture_time >= self.interval:
            ret, frame = self.cap.read()
            if ret:
                self.last_capture_time = current_time
                return frame
        return None
    
    def release(self):
        """Release camera resources."""
        if self.cap is not None:
            self.cap.release()
            self.cap = None