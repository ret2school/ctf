
import pytesseract


try:
    import Image, ImageOps, ImageEnhance, imread
except ImportError:
    from PIL import Image, ImageOps, ImageEnhance

pytesseract.pytesseract.tesseract_cmd = 'C:\\Program Files\\Tesseract-OCR\\tesseract.exe'

decode = pytesseract.image_to_string(r'C:\\Users\\justz\\Desktop\\faux\\file.png')
print(decode)






