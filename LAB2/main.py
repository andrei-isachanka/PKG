import sys
import os
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import struct


from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QLabel, QProgressBar,
    QFileDialog, QMessageBox, QHeaderView, QLineEdit, QSpinBox,
    QCheckBox
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon


# Настройка логирования
logging.basicConfig(
    level=logging.WARNING,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ImageInfo:
    """Data class to store image metadata"""
    filename: str
    size_pixels: Tuple[int, int]  # (width, height)
    resolution: Tuple[float, float]  # (dpi_x, dpi_y)
    color_depth: int  # bits per pixel
    compression: str
    file_path: str


class ImageMetadataReader:
    """Reads metadata from various image formats"""

    SUPPORTED_FORMATS = {'.jpg', '.jpeg', '.gif', '.tif', '.tiff', '.bmp', '.png', '.pcx'}

    @staticmethod
    def get_jpeg_info(file_path: str) -> Optional[ImageInfo]:
        """Extract JPEG metadata"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Проверка JPEG маркера
            if data[:2] != b'\xff\xd8':
                return None

            width, height = 0, 0
            dpi_x, dpi_y = 72, 72  
            color_depth = 24  
            compression = "JPEG (lossy)"

            # Парсинг JPEG маркеров
            i = 2
            while i < len(data) - 9:
                if data[i:i+1] != b'\xff':
                    i += 1
                    continue

                marker = data[i+1:i+2]

                # SOF маркеры содержат размеры изображения и информацию о компонентах
                if marker in (b'\xc0', b'\xc1', b'\xc2', b'\xc9', b'\xca', b'\xcb'):
                    if i + 10 > len(data):
                        break
                    
                    length = struct.unpack('>H', data[i+2:i+4])[0]
                    precision_bits = data[i+4]  
                    height = struct.unpack('>H', data[i+5:i+7])[0]
                    width = struct.unpack('>H', data[i+7:i+9])[0]
                    num_components = data[i+9]  
                    
                    color_depth = precision_bits * num_components
                    break

                if marker == b'\xe0':
                    if i + 14 > len(data):
                        i += 2
                        continue
                    
                    length = struct.unpack('>H', data[i+2:i+4])[0]
                    if i + 11 < len(data) and data[i+4:i+9] == b'JFIF\x00':
                        units = data[i+9]
                        if units == 1:  # DPI
                            dpi_x = struct.unpack('>H', data[i+10:i+12])[0]
                            dpi_y = struct.unpack('>H', data[i+12:i+14])[0]
                        elif units == 2:  # DPCm -> DPI
                            dpi_x = int(struct.unpack('>H', data[i+10:i+12])[0] * 2.54)
                            dpi_y = int(struct.unpack('>H', data[i+12:i+14])[0] * 2.54)

                if i + 4 > len(data):
                    break
                
                length = struct.unpack('>H', data[i+2:i+4])[0]
                i += length + 2

            if width > 0 and height > 0:
                return ImageInfo(
                    filename=os.path.basename(file_path),
                    size_pixels=(width, height),
                    resolution=(dpi_x, dpi_y),
                    color_depth=color_depth,
                    compression=compression,
                    file_path=file_path
                )
        except Exception as e:
            logger.warning(f"Ошибка при чтении JPEG {file_path}: {str(e)}")
        
        return None

    @staticmethod
    def get_png_info(file_path: str) -> Optional[ImageInfo]:
        """Extract PNG metadata"""
        try:
            with open(file_path, 'rb') as f:
                # Проверка PNG сигнатуры
                if f.read(8) != b'\x89PNG\r\n\x1a\n':
                    return None

                width, height = 0, 0
                color_depth = 8
                color_type = 0
                compression = "PNG (lossless)"
                dpi_x, dpi_y = 72, 72

                while True:
                    length_data = f.read(4)
                    if len(length_data) < 4:
                        break

                    length = struct.unpack('>I', length_data)[0]
                    chunk_type = f.read(4)
                    chunk_data = f.read(length)
                    f.read(4)  # CRC

                    if chunk_type == b'IHDR':
                        if length < 13:
                            break
                        
                        width = struct.unpack('>I', chunk_data[0:4])[0]
                        height = struct.unpack('>I', chunk_data[4:8])[0]
                        bits_per_sample = chunk_data[8]
                        color_type = chunk_data[9]

                        # Расчет глубины цвета на основе типа цвета
                        if color_type == 0:  # Grayscale
                            color_depth = bits_per_sample
                        elif color_type == 2:  # RGB
                            color_depth = bits_per_sample * 3
                        elif color_type == 3:  
                            color_depth = bits_per_sample
                        elif color_type == 4:  # Grayscale + Alpha
                            color_depth = bits_per_sample * 2
                        elif color_type == 6:  # RGBA
                            color_depth = bits_per_sample * 4
                        else:
                            color_depth = bits_per_sample

                    elif chunk_type == b'pHYs':
                        if length >= 9:
                            dpi_x = struct.unpack('>I', chunk_data[0:4])[0]
                            dpi_y = struct.unpack('>I', chunk_data[4:8])[0]
                            unit = chunk_data[8]
                            if unit == 1:  # Конвертация из метров в DPI
                                dpi_x = int(dpi_x / 39.3701)
                                dpi_y = int(dpi_y / 39.3701)

                    elif chunk_type == b'IEND':
                        break

                if width > 0 and height > 0:
                    return ImageInfo(
                        filename=os.path.basename(file_path),
                        size_pixels=(width, height),
                        resolution=(dpi_x, dpi_y),
                        color_depth=int(color_depth),
                        compression=compression,
                        file_path=file_path
                    )
        except Exception as e:
            logger.warning(f"Ошибка при чтении PNG {file_path}: {str(e)}")
        
        return None

    @staticmethod
    def get_gif_info(file_path: str) -> Optional[ImageInfo]:
        """Extract GIF metadata"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(6)
                if header[:3] not in (b'GIF87a', b'GIF89a'):
                    return None

                width = struct.unpack('<H', f.read(2))[0]
                height = struct.unpack('<H', f.read(2))[0]

                packed = f.read(1)[0]
                global_color_table_flag = (packed >> 7) & 1
                color_resolution = ((packed >> 4) & 0x07) + 1  # Бит на пиксель в таблице цветов
                sort_flag = (packed >> 3) & 1
                gct_size = 2 ** ((packed & 0x07) + 1)

                color_depth = color_resolution
                
                num_colors = 2 ** color_resolution
                compression = f"GIF (lossless, {num_colors} colors)"
                dpi_x, dpi_y = 72, 72  # GIF не хранит DPI

                if width > 0 and height > 0:
                    return ImageInfo(
                        filename=os.path.basename(file_path),
                        size_pixels=(width, height),
                        resolution=(dpi_x, dpi_y),
                        color_depth=color_depth,
                        compression=compression,
                        file_path=file_path
                    )
        except Exception as e:
            logger.warning(f"Ошибка при чтении GIF {file_path}: {str(e)}")
        
        return None

    @staticmethod
    def get_bmp_info(file_path: str) -> Optional[ImageInfo]:
        """Extract BMP metadata"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(2)
                if header != b'BM':
                    return None

                f.seek(18)
                width = struct.unpack('<I', f.read(4))[0]
                height = struct.unpack('<I', f.read(4))[0]

                f.seek(28)
                color_depth = struct.unpack('<H', f.read(2))[0]
                compression = struct.unpack('<I', f.read(4))[0]

                compression_str = "BMP (uncompressed)"
                if compression == 1:
                    compression_str = "BMP (RLE 8-bit)"
                elif compression == 2:
                    compression_str = "BMP (RLE 4-bit)"

                dpi_x, dpi_y = 72, 72
                
                f.seek(14)
                header_size = struct.unpack('<I', f.read(4))[0]
                
                if header_size >= 40:
                    f.seek(38)
                    pixels_per_meter_x = struct.unpack('<I', f.read(4))[0]
                    pixels_per_meter_y = struct.unpack('<I', f.read(4))[0]
                    
                    if pixels_per_meter_x > 0:
                        dpi_x = round(pixels_per_meter_x / 39.3701)
                    if pixels_per_meter_y > 0:
                        dpi_y = round(pixels_per_meter_y / 39.3701)

                if width > 0 and height > 0:
                    return ImageInfo(
                        filename=os.path.basename(file_path),
                        size_pixels=(width, height),
                        resolution=(dpi_x, dpi_y),
                        color_depth=color_depth,
                        compression=compression_str,
                        file_path=file_path
                    )
        except Exception as e:
            logger.warning(f"Ошибка при чтении BMP {file_path}: {str(e)}")
        
        return None

    @staticmethod
    def get_tiff_info(file_path: str) -> Optional[ImageInfo]:
        """Extract TIFF metadata"""
        try:
            with open(file_path, 'rb') as f:
                byte_order_marker = f.read(2)
                if byte_order_marker == b'II':
                    endian = '<'
                elif byte_order_marker == b'MM':
                    endian = '>'
                else:
                    return None

                magic = struct.unpack(endian + 'H', f.read(2))[0]
                if magic != 42:
                    return None

                ifd_offset = struct.unpack(endian + 'I', f.read(4))[0]
                f.seek(ifd_offset)

                num_tags = struct.unpack(endian + 'H', f.read(2))[0]

                width, height = 0, 0
                color_depth = 1
                compression = "TIFF (uncompressed)"
                dpi_x, dpi_y = 72, 72
                bits_per_sample = 1
                num_components = 1
                photometric = 1

                for _ in range(num_tags):
                    if f.tell() + 12 > os.path.getsize(file_path):
                        break
                    
                    tag = struct.unpack(endian + 'H', f.read(2))[0]
                    field_type = struct.unpack(endian + 'H', f.read(2))[0]
                    count = struct.unpack(endian + 'I', f.read(4))[0]
                    value_offset = f.read(4)

                    if tag == 0x0100:  # ImageWidth
                        width = struct.unpack(endian + 'I', value_offset)[0]
                    elif tag == 0x0101:  # ImageLength 
                        height = struct.unpack(endian + 'I', value_offset)[0]
                    elif tag == 0x0102:  
                        bits_per_sample = struct.unpack(endian + 'H', value_offset[:2])[0]
                    elif tag == 0x0103:  # Compression
                        comp_type = struct.unpack(endian + 'H', value_offset[:2])[0]
                        compression_types = {
                            1: "TIFF (uncompressed)",
                            2: "TIFF (CCITT 1D)",
                            3: "TIFF (Group 3 Fax)",
                            4: "TIFF (Group 4 Fax)",
                            5: "TIFF (LZW)",
                            6: "TIFF (JPEG)",
                        }
                        compression = compression_types.get(comp_type, "TIFF (unknown)")
                    elif tag == 0x0106:  
                        photometric = struct.unpack(endian + 'H', value_offset[:2])[0]
                    elif tag == 0x0115:  
                        num_components = struct.unpack(endian + 'H', value_offset[:2])[0]

                
                if photometric == 1:  
                    color_depth = bits_per_sample
                elif photometric == 2:
                    color_depth = bits_per_sample * 3
                elif photometric == 5:  
                    color_depth = bits_per_sample * 4
                else:
                    
                    color_depth = bits_per_sample * num_components

                if width > 0 and height > 0:
                    return ImageInfo(
                        filename=os.path.basename(file_path),
                        size_pixels=(width, height),
                        resolution=(dpi_x, dpi_y),
                        color_depth=color_depth,
                        compression=compression,
                        file_path=file_path
                    )
        except Exception as e:
            logger.warning(f"Ошибка при чтении TIFF {file_path}: {str(e)}")
        
        return None

    @staticmethod
    def get_pcx_info(file_path: str) -> Optional[ImageInfo]:
        """Extract PCX metadata"""
        try:
            with open(file_path, 'rb') as f:
                manufacturer = f.read(1)[0]
                if manufacturer != 0x0A:
                    return None

                version = f.read(1)[0]
                encoding = f.read(1)[0]
                bits_per_pixel = f.read(1)[0]

                x1 = struct.unpack('<H', f.read(2))[0]
                y1 = struct.unpack('<H', f.read(2))[0]
                x2 = struct.unpack('<H', f.read(2))[0]
                y2 = struct.unpack('<H', f.read(2))[0]

                width = x2 - x1 + 1
                height = y2 - y1 + 1

                f.seek(8)
                hdpi = struct.unpack('<H', f.read(2))[0]
                vdpi = struct.unpack('<H', f.read(2))[0]

                if hdpi == 0:
                    hdpi = 72
                if vdpi == 0:
                    vdpi = 72

                f.seek(65)
                num_color_planes = f.read(1)[0]
                bytes_per_line = struct.unpack('<H', f.read(2))[0]

                color_depth = bits_per_pixel * num_color_planes
                compression = "PCX (RLE)" if encoding == 1 else "PCX (uncompressed)"

                if width > 0 and height > 0:
                    return ImageInfo(
                        filename=os.path.basename(file_path),
                        size_pixels=(width, height),
                        resolution=(hdpi, vdpi),
                        color_depth=color_depth,
                        compression=compression,
                        file_path=file_path
                    )
        except Exception as e:
            logger.warning(f"Ошибка при чтении PCX {file_path}: {str(e)}")
        
        return None

    @staticmethod
    def read_image_info(file_path: str) -> Optional[ImageInfo]:
        """Read metadata from image file"""
        ext = Path(file_path).suffix.lower()

        if ext in ('.jpg', '.jpeg'):
            return ImageMetadataReader.get_jpeg_info(file_path)
        elif ext == '.png':
            return ImageMetadataReader.get_png_info(file_path)
        elif ext == '.gif':
            return ImageMetadataReader.get_gif_info(file_path)
        elif ext == '.bmp':
            return ImageMetadataReader.get_bmp_info(file_path)
        elif ext in ('.tif', '.tiff'):
            return ImageMetadataReader.get_tiff_info(file_path)
        elif ext == '.pcx':
            return ImageMetadataReader.get_pcx_info(file_path)

        return None


class ImageScannerThread(QThread):
    """Thread for scanning images to avoid blocking UI"""
    progress_updated = Signal(int)
    file_processed = Signal(ImageInfo)
    scan_completed = Signal(int)
    error_occurred = Signal(str)

    def __init__(self, folder_path: str, max_workers: int = 8):
        super().__init__()
        self.folder_path = folder_path
        self.max_workers = max_workers
        self.is_running = True

    def run(self):
        try:
            image_files = []
            supported_exts = ImageMetadataReader.SUPPORTED_FORMATS

            for root, dirs, files in os.walk(self.folder_path):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in supported_exts):
                        image_files.append(os.path.join(root, file))

            total_files = len(image_files)

            if total_files == 0:
                self.error_occurred.emit("Не найдены поддерживаемые файлы изображений")
                return

            processed_count = 0

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(ImageMetadataReader.read_image_info, file_path): file_path 
                    for file_path in image_files
                }

                for future in as_completed(futures):
                    if not self.is_running:
                        break

                    try:
                        result = future.result()
                        if result:
                            self.file_processed.emit(result)
                        processed_count += 1
                        self.progress_updated.emit(int((processed_count / total_files) * 100))
                    except Exception as e:
                        file_path = futures[future]
                        logger.warning(f"Ошибка при обработке {file_path}: {str(e)}")
                        processed_count += 1
                        self.progress_updated.emit(int((processed_count / total_files) * 100))

            self.scan_completed.emit(total_files)
        except Exception as e:
            logger.error(f"Ошибка при сканировании: {str(e)}")
            self.error_occurred.emit(f"Ошибка при сканировании: {str(e)}")

    def stop(self):
        self.is_running = False


class ImageInfoApp(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Image Metadata Viewer")
        self.setGeometry(100, 100, 1400, 700)

        self.image_infos: List[ImageInfo] = []
        self.scanner_thread: Optional[ImageScannerThread] = None

        self.init_ui()

    def init_ui(self):
        """Initialize user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)

        # Top controls
        control_layout = QHBoxLayout()

        self.folder_path_label = QLineEdit()
        self.folder_path_label.setReadOnly(True)
        self.folder_path_label.setPlaceholderText("Выберите папку с изображениями...")

        browse_btn = QPushButton("Выбрать папку")
        browse_btn.clicked.connect(self.browse_folder)

        self.max_workers_spin = QSpinBox()
        self.max_workers_spin.setMinimum(1)
        self.max_workers_spin.setMaximum(32)
        self.max_workers_spin.setValue(8)
        self.max_workers_spin.setMaximumWidth(100)

        control_layout.addWidget(QLabel("Папка:"))
        control_layout.addWidget(self.folder_path_label)
        control_layout.addWidget(browse_btn)
        control_layout.addWidget(QLabel("Потоков:"))
        control_layout.addWidget(self.max_workers_spin)
        control_layout.addStretch()

        layout.addLayout(control_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Имя файла",
            "Размер (пиксели)",
            "Разрешение (dpi)",
            "Глубина цвета (бит)",
            "Сжатие",
            "Путь"
        ])

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.Stretch)

        self.table.setColumnHidden(5, True)  # Hide full path

        layout.addWidget(self.table)

        # Status bar
        self.status_label = QLabel("Готово")
        self.statusBar().addWidget(self.status_label)

    def browse_folder(self):
        """Browse for folder"""
        folder_path = QFileDialog.getExistingDirectory(self, "Выберите папку с изображениями")

        if folder_path:
            self.folder_path_label.setText(folder_path)
            self.scan_images(folder_path)

    def scan_images(self, folder_path: str):
        """Start image scanning"""
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.scanner_thread.wait()

        self.image_infos.clear()
        self.table.setRowCount(0)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Сканирование...")

        self.scanner_thread = ImageScannerThread(folder_path, self.max_workers_spin.value())
        self.scanner_thread.file_processed.connect(self.add_image_to_table)
        self.scanner_thread.progress_updated.connect(self.update_progress)
        self.scanner_thread.scan_completed.connect(self.scan_completed)
        self.scanner_thread.error_occurred.connect(self.show_error)
        self.scanner_thread.start()

    def add_image_to_table(self, image_info: ImageInfo):
        """Add image info to table"""
        self.image_infos.append(image_info)

        row = self.table.rowCount()
        self.table.insertRow(row)

        # Filename
        self.table.setItem(row, 0, QTableWidgetItem(image_info.filename))

        # Size
        size_text = f"{image_info.size_pixels[0]}×{image_info.size_pixels[1]}"
        self.table.setItem(row, 1, QTableWidgetItem(size_text))

        # Resolution
        dpi_text = f"{image_info.resolution[0]:.0f}×{image_info.resolution[1]:.0f}"
        self.table.setItem(row, 2, QTableWidgetItem(dpi_text))

        # Color depth
        self.table.setItem(row, 3, QTableWidgetItem(str(image_info.color_depth)))

        # Compression
        self.table.setItem(row, 4, QTableWidgetItem(image_info.compression))

        # Path (hidden)
        self.table.setItem(row, 5, QTableWidgetItem(image_info.file_path))

    def update_progress(self, value: int):
        """Update progress bar"""
        self.progress_bar.setValue(value)

    def scan_completed(self, total_files: int):
        """Scan completed"""
        self.progress_bar.setVisible(False)
        self.status_label.setText(
            f"Завершено. Найдено и обработано {len(self.image_infos)} файлов "
            f"из {total_files} в папке"
        )

    def show_error(self, error_message: str):
        """Show error message"""
        QMessageBox.critical(self, "Ошибка", error_message)
        self.status_label.setText("Ошибка при сканировании")
        self.progress_bar.setVisible(False)


def main():
    app = QApplication(sys.argv)
    window = ImageInfoApp()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()