import tkinter as tk
import argparse
import sys
import os

def create_custom_dialog(title, message, buttons):
    root = tk.Tk()
    root.overrideredirect(True)  # Remove window borders
    root.attributes('-topmost', True)

    # Set window size and position
    width, height = 400, 200
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")

    # Main canvas with fake rounded corners
    canvas = tk.Canvas(root, width=width, height=height, bg="#1e1e1e", highlightthickness=0)
    canvas.pack()

    # Rounded rectangle background (simulate corners)
    def round_rect(x1, y1, x2, y2, r=20, **kwargs):
        points = [
            x1+r, y1,
            x2-r, y1,
            x2, y1,
            x2, y1+r,
            x2, y2-r,
            x2, y2,
            x2-r, y2,
            x1+r, y2,
            x1, y2,
            x1, y2-r,
            x1, y1+r,
            x1, y1
        ]
        return canvas.create_polygon(points, **kwargs, smooth=True)

    round_rect(0, 0, width, height, r=20, fill="#1e1e1e")

    # Title bar (for dragging and close button)
    def start_move(event):
        root.x = event.x
        root.y = event.y

    def stop_move(event):
        root.x = None
        root.y = None

    def do_move(event):
        x = event.x_root - root.x
        y = event.y_root - root.y
        root.geometry(f"+{x}+{y}")

    titlebar = tk.Frame(root, bg="#111111", height=30)
    titlebar.place(x=0, y=0, width=width)
    titlebar.bind("<Button-1>", start_move)
    titlebar.bind("<B1-Motion>", do_move)

    # Close button
    def close():
        print("Closed via X")
        sys.exit(-1)

    close_btn = tk.Button(titlebar, text="✕", bg="#111111", fg="white", bd=0, command=close)
    close_btn.place(x=width-30, y=5, width=20, height=20)

    # Exclamation icon
    icon = tk.Label(root, text="⚠", font=("Segoe UI", 32), bg="#1e1e1e", fg="yellow")
    icon.place(x=20, y=50)

    # Message text
    label = tk.Label(root, text=message, font=("Segoe UI", 12), wraplength=300,
                     bg="#1e1e1e", fg="white", justify="left")
    label.place(x=80, y=50)

    # Button container
    result = [None]
    btn_frame = tk.Frame(root, bg="#1e1e1e")
    btn_frame.place(x=0, y=height-60, width=width)

    def on_click(index):
        result[0] = index
        root.destroy()
        print(index)
        sys.exit(index)

    for idx, name in enumerate(buttons):
        b = tk.Button(btn_frame, text=name, width=10, bg="#333", fg="white", bd=0,
                      command=lambda i=idx: on_click(i))
        b.pack(side=tk.LEFT, padx=10, pady=10)

    root.mainloop()

def main():
    parser = argparse.ArgumentParser(description='Display modern custom message box')
    parser.add_argument('-T', '--title', default='Warning', help='Window title')
    parser.add_argument('-m', '--message', default='Something happened.', help='Message text')
    parser.add_argument('-b', '--buttons', nargs='+', default=['OK'], help='Buttons to show')
    args = parser.parse_args()

    create_custom_dialog(args.title, args.message, args.buttons)

if __name__ == "__main__":
    main()
