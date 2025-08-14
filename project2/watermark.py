import numpy as np
import cv2
from matplotlib import pyplot as plt
import os
from tkinter import Tk, filedialog, Button, Label, messagebox, Entry, StringVar, Radiobutton
from PIL import Image, ImageTk

class WatermarkSystem:
    def __init__(self):
        self.host_img = None
        self.watermark = None
        self.watermarked_img = None
        self.attacked_imgs = {}
        
    def load_image(self, is_watermark=False):
        root = Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(
            title="选择水印图片" if is_watermark else "选择宿主图片",
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp *.tif")]
        )
        root.destroy()
        
        if not file_path:
            return None
            
        img = cv2.imread(file_path)
        if img is None:
            messagebox.showerror("错误", "无法加载图像文件")
            return None
            
        if is_watermark:
            self.watermark = img
        else:
            self.host_img = img
            
        return img
    
    def embed_watermark_dct(self, alpha=0.1):
        if self.host_img is None or self.watermark is None:
            messagebox.showerror("错误", "请先加载宿主图片和水印图片")
            return None
            
        img_yuv = cv2.cvtColor(self.host_img, cv2.COLOR_BGR2YUV)
        y_channel = img_yuv[:,:,0].astype(np.float32)
        
        dct = cv2.dct(y_channel)
        
        watermark_gray = cv2.cvtColor(self.watermark, cv2.COLOR_BGR2GRAY)
        watermark_resized = cv2.resize(watermark_gray, (dct.shape[1], dct.shape[0]))
        watermark_normalized = watermark_resized.astype(np.float32) / 255.0
        
        rows, cols = dct.shape
        for i in range(rows):
            for j in range(cols):
                if i > rows/4 and i < 3*rows/4 and j > cols/4 and j < 3*cols/4:
                    dct[i,j] += alpha * watermark_normalized[i,j]
        
        idct = cv2.idct(dct)
        
        img_yuv[:,:,0] = np.clip(idct, 0, 255)
        self.watermarked_img = cv2.cvtColor(img_yuv, cv2.COLOR_YUV2BGR)
        
        return self.watermarked_img
    
    def extract_watermark_dct(self, alpha=0.1):
        if self.watermarked_img is None or self.host_img is None:
            messagebox.showerror("错误", "请先嵌入水印并确保有原始宿主图片")
            return None
            
        wm_yuv = cv2.cvtColor(self.watermarked_img, cv2.COLOR_BGR2YUV)
        orig_yuv = cv2.cvtColor(self.host_img, cv2.COLOR_BGR2YUV)
        
        wm_y = wm_yuv[:,:,0].astype(np.float32)
        orig_y = orig_yuv[:,:,0].astype(np.float32)
        
        wm_dct = cv2.dct(wm_y)
        orig_dct = cv2.dct(orig_y)
        
        extracted = (wm_dct - orig_dct) / alpha
        extracted = np.clip(extracted * 255, 0, 255).astype(np.uint8)
        
        if self.watermark is not None:
            extracted = cv2.resize(extracted, (self.watermark.shape[1], self.watermark.shape[0]))
        
        return extracted
    
    def embed_watermark_lsb(self):
        if self.host_img is None or self.watermark is None:
            messagebox.showerror("错误", "请先加载宿主图片和水印图片")
            return None
            
        if len(self.watermark.shape) > 2:
            watermark_gray = cv2.cvtColor(self.watermark, cv2.COLOR_BGR2GRAY)
        else:
            watermark_gray = self.watermark
            
        _, watermark_binary = cv2.threshold(watermark_gray, 127, 1, cv2.THRESH_BINARY)
        
        watermark_resized = cv2.resize(watermark_binary, (self.host_img.shape[1], self.host_img.shape[0]))
        
        watermarked_img = self.host_img.copy()
        
        for i in range(watermark_resized.shape[0]):
            for j in range(watermark_resized.shape[1]):
                for k in range(3):
                    watermarked_img[i,j,k] = (self.host_img[i,j,k] & 0xFE) | watermark_resized[i,j]
        
        self.watermarked_img = watermarked_img
        return watermarked_img
    
    def extract_watermark_lsb(self):
        if self.watermarked_img is None:
            messagebox.showerror("错误", "请先嵌入水印")
            return None
            
        if self.watermark is not None:
            watermark_shape = (self.watermark.shape[0], self.watermark.shape[1])
        else:
            watermark_shape = (self.watermarked_img.shape[0], self.watermarked_img.shape[1])
            
        extracted = np.zeros(watermark_shape, dtype=np.uint8)
        
        for i in range(min(watermark_shape[0], self.watermarked_img.shape[0])):
            for j in range(min(watermark_shape[1], self.watermarked_img.shape[1])):
                extracted[i,j] = (self.watermarked_img[i,j,0] & 1) * 255
        
        return extracted
    
    def rotate_image(self, img, angle):
        rows, cols = img.shape[:2]
        M = cv2.getRotationMatrix2D((cols/2,rows/2), angle, 1)
        return cv2.warpAffine(img, M, (cols,rows))
    
    def adjust_contrast(self, img, alpha):
        return cv2.convertScaleAbs(img, alpha=alpha, beta=0)
    
    def add_noise(self, img, mean, sigma):
        noise = np.random.normal(mean, sigma, img.shape) * 255
        noisy_img = img + noise
        return np.clip(noisy_img, 0, 255).astype(np.uint8)
    
    def jpeg_compression(self, img, quality):
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
        _, encimg = cv2.imencode('.jpg', img, encode_param)
        return cv2.imdecode(encimg, 1)
    
    def crop_image(self, img, ratio):
        h, w = img.shape[:2]
        return img[int(h*ratio):, int(w*ratio):]
    
    def robustness_test(self):
        if self.watermarked_img is None:
            messagebox.showerror("错误", "请先嵌入水印")
            return None
            
        self.attacked_imgs = {
            '旋转30度': self.rotate_image(self.watermarked_img, 30),
            '水平翻转': cv2.flip(self.watermarked_img, 1),
            '裁剪20%': self.crop_image(self.watermarked_img, 0.2),
            '对比度增加1.5x': self.adjust_contrast(self.watermarked_img, 1.5),
            '对比度减少0.7x': self.adjust_contrast(self.watermarked_img, 0.7),
            '添加高斯噪声': self.add_noise(self.watermarked_img, 0, 0.02),
            'JPEG压缩(质量90)': self.jpeg_compression(self.watermarked_img, 90),
            'JPEG压缩(质量70)': self.jpeg_compression(self.watermarked_img, 70)
        }
        
        return self.attacked_imgs
    
    def save_image(self, img, default_name="output.png"):
        root = Tk()
        root.withdraw()
        file_path = filedialog.asksaveasfilename(
            title="保存图片",
            initialfile=default_name,
            filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg *.jpeg"), ("All files", "*.*")]
        )
        root.destroy()
        
        if file_path:
            cv2.imwrite(file_path, img)
            messagebox.showinfo("成功", f"图片已保存到: {file_path}")

class WatermarkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("基于数字水印的图片泄露检测系统")
        self.root.geometry("800x600")
        
        self.system = WatermarkSystem()
        self.method_var = StringVar(value="dct")
        self.alpha_var = StringVar(value="0.1")
        
        self.create_widgets()
        
    def create_widgets(self):
        top_frame = Label(self.root)
        top_frame.pack(pady=10)
        
        Button(top_frame, text="加载宿主图片", command=self.load_host_img).pack(side="left", padx=5)
        Button(top_frame, text="加载水印图片", command=self.load_watermark_img).pack(side="left", padx=5)
        
        method_frame = Label(self.root, text="水印方法选择")
        method_frame.pack(pady=5)
        
        Radiobutton(method_frame, text="DCT方法", variable=self.method_var, value="dct").pack(side="left", padx=10)
        Radiobutton(method_frame, text="LSB方法", variable=self.method_var, value="lsb").pack(side="left", padx=10)
        
        Label(method_frame, text="DCT参数alpha:").pack(side="left", padx=5)
        Entry(method_frame, textvariable=self.alpha_var, width=5).pack(side="left")
        
        btn_frame = Label(self.root)
        btn_frame.pack(pady=10)
        
        Button(btn_frame, text="嵌入水印", command=self.embed_watermark).pack(side="left", padx=5)
        Button(btn_frame, text="提取水印", command=self.extract_watermark).pack(side="left", padx=5)
        Button(btn_frame, text="鲁棒性测试", command=self.run_robustness_test).pack(side="left", padx=5)
        
        self.result_label = Label(self.root)
        self.result_label.pack(pady=10, fill="both", expand=True)
        
        Button(self.root, text="保存结果", command=self.save_result).pack(pady=10)
    
    def load_host_img(self):
        img = self.system.load_image(is_watermark=False)
        if img is not None:
            self.show_image(img, "宿主图片")
    
    def load_watermark_img(self):
        img = self.system.load_image(is_watermark=True)
        if img is not None:
            self.show_image(img, "水印图片")
    
    def embed_watermark(self):
        method = self.method_var.get()
        if method == "dct":
            try:
                alpha = float(self.alpha_var.get())
                watermarked = self.system.embed_watermark_dct(alpha)
            except ValueError:
                messagebox.showerror("错误", "请输入有效的alpha值")
                return
        else:
            watermarked = self.system.embed_watermark_lsb()
        
        if watermarked is not None:
            self.show_image(watermarked, "含水印图片")
    
    def extract_watermark(self):
        method = self.method_var.get()
        if method == "dct":
            try:
                alpha = float(self.alpha_var.get())
                extracted = self.system.extract_watermark_dct(alpha)
            except ValueError:
                messagebox.showerror("错误", "请输入有效的alpha值")
                return
        else:
            extracted = self.system.extract_watermark_lsb()
        
        if extracted is not None:
            self.show_image(extracted, "提取的水印", grayscale=True)
    
    def run_robustness_test(self):
        attacked_imgs = self.system.robustness_test()
        if attacked_imgs is not None:
            first_key = list(attacked_imgs.keys())[0]
            self.show_image(attacked_imgs[first_key], f"攻击测试: {first_key}")
            
            method = self.method_var.get()
            if method == "dct":
                try:
                    alpha = float(self.alpha_var.get())
                    extracted = self.system.extract_watermark_dct(alpha)
                except ValueError:
                    messagebox.showerror("错误", "请输入有效的alpha值")
                    return
            else:
                extracted = self.system.extract_watermark_lsb()
            
            if extracted is not None:
                self.show_image(extracted, "从攻击图片中提取的水印", grayscale=True)
    
    def save_result(self):
        if self.system.watermarked_img is not None:
            self.system.save_image(self.system.watermarked_img, "watermarked.png")
        else:
            messagebox.showerror("错误", "没有可保存的结果")
    
    def show_image(self, img, title="", grayscale=False):
        max_size = (600, 400)
        h, w = img.shape[:2]
        ratio = min(max_size[0]/w, max_size[1]/h)
        new_size = (int(w*ratio), int(h*ratio))
        
        if len(img.shape) == 3 and img.shape[2] == 3 and not grayscale:
            img_display = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        elif grayscale:
            img_display = cv2.cvtColor(img, cv2.COLOR_GRAY2RGB) if len(img.shape) == 2 else img
        else:
            img_display = img
            
        img_pil = Image.fromarray(img_display)
        img_pil = img_pil.resize(new_size, Image.LANCZOS)
        img_tk = ImageTk.PhotoImage(img_pil)
        
        self.result_label.config(text=title)
        self.result_label.image = img_tk
        self.result_label.configure(image=img_tk)

if __name__ == "__main__":
    root = Tk()
    app = WatermarkApp(root)
    root.mainloop()