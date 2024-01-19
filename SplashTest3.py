import tkinter as tk
from PIL import Image, ImageTk
import os

# Path to the image
image_path = 'c:\\temp\\AdvanceA.jpg'

# Check if the image exists
if not os.path.exists(image_path):
    print(f"Image not found at %7Bimage_path%7D. Please check the file path.")
else:
    # Create a Tkinter window
    root = tk.Tk()
    root.overrideredirect(True)  # Remove window border and title bar

    # Load the image
    img = Image.open(image_path)
    photo = ImageTk.PhotoImage(img)

    # Create a label to display the image
    label = tk.Label(root, image=photo)
    label.pack()

    # Center the splash screen
    ws = root.winfo_screenwidth()
    hs = root.winfo_screenheight()
    x = (ws/2) - (img.width/2)
    y = (hs/2) - (img.height/2)
    root.geometry(f'+%7Bint(x)%7D+%7Bint(y)%7D')

    # Display the splash screen for 10 seconds then destroy
    root.after(10000, root.destroy)  # 10000ms = 10s

    root.mainloop()