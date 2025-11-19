import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QDoubleSpinBox, QSlider, QPushButton, QGroupBox,
    QGridLayout, QColorDialog
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPalette


class ColorConverter:
    
    @staticmethod
     # Нормализация RGB к диапазону 0-1
    def rgb_to_xyz(r, g, b):
        r, g, b = r / 255.0, g / 255.0, b / 255.0
        
        def gamma_correction(channel):
            if channel <= 0.04045:
                return channel / 12.92
            else:
                return ((channel + 0.055) / 1.055) ** 2.4
        
        r = gamma_correction(r)
        g = gamma_correction(g)
        b = gamma_correction(b)
        
        #Матрица преобразования D65
        x = r * 0.4124564 + g * 0.3575761 + b * 0.1804375
        y = r * 0.2126729 + g * 0.7151522 + b * 0.0721750
        z = r * 0.0193339 + g * 0.1191920 + b * 0.9503041
        
        return x * 100, y * 100, z * 100
    
    @staticmethod
    def xyz_to_rgb(x, y, z):
        x, y, z = x / 100.0, y / 100.0, z / 100.0
     
        r = x * 3.2404542 + y * -1.5371385 + z * -0.4985314
        g = x * -0.9692660 + y * 1.8760108 + z * 0.0415560
        b = x * 0.0556434 + y * -0.2040259 + z * 1.0572252
        
        def inverse_gamma(channel):
            if channel <= 0.0031308:
                return channel * 12.92
            else:
                return 1.055 * (channel ** (1/2.4)) - 0.055
        
        r = inverse_gamma(r)
        g = inverse_gamma(g)
        b = inverse_gamma(b)
        
        r = r * 255.0
        g = g * 255.0
        b = b * 255.0
        
        clipped = False
        if r < 0 or r > 255 or g < 0 or g > 255 or b < 0 or b > 255:
            clipped = True
        
        r = max(0, min(255, r))
        g = max(0, min(255, g))
        b = max(0, min(255, b))
        
        return r, g, b, clipped
    
    @staticmethod
    def xyz_to_lab(x, y, z):
        ref_x = 95.047
        ref_y = 100.000
        ref_z = 108.883
        
        x = x / ref_x
        y = y / ref_y
        z = z / ref_z
        
        def f(t):
            delta = 6/29
            if t > delta**3:
                return t**(1/3)
            else:
                return t/(3*delta**2) + 4/29
        
        fx = f(x)
        fy = f(y)
        fz = f(z)
        
        L = 116 * fy - 16
        a = 500 * (fx - fy)
        b = 200 * (fy - fz)
        
        return L, a, b
    
    @staticmethod
    def lab_to_xyz(L, a, b):
        #Референсные значения
        ref_x = 95.047
        ref_y = 100.000
        ref_z = 108.883
        
        fy = (L + 16) / 116
        fx = a / 500 + fy
        fz = fy - b / 200
        
        def f_inv(t):
            delta = 6/29
            if t > delta:
                return t**3
            else:
                return 3 * delta**2 * (t - 4/29)
        
        x = ref_x * f_inv(fx)
        y = ref_y * f_inv(fy)
        z = ref_z * f_inv(fz)
        
        return x, y, z


class ColorModelWidget(QGroupBox):
    
    value_changed = Signal()
    
    def __init__(self, title, component_names, ranges):
        super().__init__(title)
        self.component_names = component_names
        self.ranges = ranges
        self.updating = False
        
        self.spinboxes = []
        self.sliders = []
        
        layout = QGridLayout()
        
        for i, (name, (min_val, max_val)) in enumerate(zip(component_names, ranges)):
            label = QLabel(f"{name}:")
            layout.addWidget(label, i, 0)
            
            spinbox = QDoubleSpinBox()
            spinbox.setMinimum(min_val)
            spinbox.setMaximum(max_val)
            spinbox.setDecimals(2)
            spinbox.setValue(0)
            spinbox.valueChanged.connect(lambda _, idx=i: self.on_spinbox_changed(idx))
            layout.addWidget(spinbox, i, 1)
            self.spinboxes.append(spinbox)
            
            slider = QSlider(Qt.Horizontal)
            slider.setMinimum(0)
            slider.setMaximum(1000)
            slider.setValue(0)
            slider.valueChanged.connect(lambda _, idx=i: self.on_slider_changed(idx))
            layout.addWidget(slider, i, 2)
            self.sliders.append(slider)
        
        self.setLayout(layout)
    
    def on_spinbox_changed(self, index):
        if not self.updating:
            self.updating = True
            value = self.spinboxes[index].value()
            min_val, max_val = self.ranges[index]
            normalized = (value - min_val) / (max_val - min_val)
            self.sliders[index].setValue(int(normalized * 1000))
            self.updating = False
            self.value_changed.emit()
    
    def on_slider_changed(self, index):
        if not self.updating:
            self.updating = True
            slider_value = self.sliders[index].value()
            min_val, max_val = self.ranges[index]
            value = min_val + (slider_value / 1000.0) * (max_val - min_val)
            self.spinboxes[index].setValue(value)
            self.updating = False
            self.value_changed.emit()
    
    def get_values(self):
        return [spinbox.value() for spinbox in self.spinboxes]
    
    def set_values(self, values):
        self.updating = True
        for i, value in enumerate(values):
            self.spinboxes[i].setValue(value)
            min_val, max_val = self.ranges[i]
            normalized = (value - min_val) / (max_val - min_val)
            self.sliders[i].setValue(int(normalized * 1000))
        self.updating = False


class ColorConverterApp(QMainWindow):
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Цветовые модели - Вариант 3: RGB ↔ XYZ ↔ LAB")
        self.setMinimumSize(800, 600)
        
        self.converter = ColorConverter()
        self.current_source = None  
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        self.color_display = QWidget()
        self.color_display.setMinimumHeight(100)
        self.color_display.setAutoFillBackground(True)
        self.update_color_display(255, 255, 255)
        main_layout.addWidget(QLabel("Текущий цвет:"))
        main_layout.addWidget(self.color_display)
        
        color_picker_btn = QPushButton("Выбрать цвет из палитры")
        color_picker_btn.clicked.connect(self.pick_color)
        main_layout.addWidget(color_picker_btn)
        
        models_layout = QHBoxLayout()
        
        self.rgb_widget = ColorModelWidget(
            "RGB",
            ["R", "G", "B"],
            [(0, 255), (0, 255), (0, 255)]
        )
        self.rgb_widget.value_changed.connect(lambda: self.on_model_changed('rgb'))
        models_layout.addWidget(self.rgb_widget)
        
        self.xyz_widget = ColorModelWidget(
            "XYZ",
            ["X", "Y", "Z"],
            [(0, 100), (0, 100), (0, 100)]
        )
        self.xyz_widget.value_changed.connect(lambda: self.on_model_changed('xyz'))
        models_layout.addWidget(self.xyz_widget)
        
        self.lab_widget = ColorModelWidget(
            "LAB",
            ["L", "a", "b"],
            [(0, 100), (-128, 127), (-128, 127)]
        )
        self.lab_widget.value_changed.connect(lambda: self.on_model_changed('lab'))
        models_layout.addWidget(self.lab_widget)
        
        main_layout.addLayout(models_layout)
        
        self.warning_label = QLabel("")
        self.warning_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(self.warning_label)
        
        #инициализация белым цветом
        self.rgb_widget.set_values([255, 255, 255])
        self.on_model_changed('rgb')
    
    def on_model_changed(self, source):
        if self.current_source == source:
            return
        
        self.current_source = source
        self.warning_label.setText("")
        
        try:
            if source == 'rgb':
                r, g, b = self.rgb_widget.get_values()
                x, y, z = self.converter.rgb_to_xyz(r, g, b)
                L, a, b_lab = self.converter.xyz_to_lab(x, y, z)
                
                self.xyz_widget.set_values([x, y, z])
                self.lab_widget.set_values([L, a, b_lab])
                self.update_color_display(r, g, b)
            
            elif source == 'xyz':
                x, y, z = self.xyz_widget.get_values()
                r, g, b, clipped = self.converter.xyz_to_rgb(x, y, z)
                L, a, b_lab = self.converter.xyz_to_lab(x, y, z)
                
                self.rgb_widget.set_values([r, g, b])
                self.lab_widget.set_values([L, a, b_lab])
                self.update_color_display(r, g, b)
                
                if clipped:
                    self.warning_label.setText("Значения RGB были обрезаны до допустимого диапазона")
            
            elif source == 'lab':
                L, a, b_lab = self.lab_widget.get_values()
                x, y, z = self.converter.lab_to_xyz(L, a, b_lab)
                r, g, b, clipped = self.converter.xyz_to_rgb(x, y, z)
                
                self.xyz_widget.set_values([x, y, z])
                self.rgb_widget.set_values([r, g, b])
                self.update_color_display(r, g, b)
                
                if clipped:
                    self.warning_label.setText("Значения RGB были обрезаны до допустимого диапазона")
        
        finally:
            self.current_source = None
    
    def update_color_display(self, r, g, b):
        palette = self.color_display.palette()
        palette.setColor(QPalette.Window, QColor(int(r), int(g), int(b)))
        self.color_display.setPalette(palette)
    
    def pick_color(self):
        color = QColorDialog.getColor()
        if color.isValid():
            self.rgb_widget.set_values([color.red(), color.green(), color.blue()])
            self.on_model_changed('rgb')


def main():
    app = QApplication(sys.argv)
    window = ColorConverterApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()