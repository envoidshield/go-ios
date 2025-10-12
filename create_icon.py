#!/usr/bin/env python3
"""
Simple script to create an icon for the iOS Tunnel Manager GUI
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_icon():
    # Create a 256x256 icon
    size = 256
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw a phone-like shape
    phone_width = 120
    phone_height = 200
    phone_x = (size - phone_width) // 2
    phone_y = (size - phone_height) // 2
    
    # Phone body (rounded rectangle)
    draw.rounded_rectangle(
        [phone_x, phone_y, phone_x + phone_width, phone_y + phone_height],
        radius=20,
        fill=(50, 50, 50, 255),
        outline=(100, 100, 100, 255),
        width=3
    )
    
    # Screen
    screen_margin = 15
    draw.rounded_rectangle(
        [phone_x + screen_margin, phone_y + screen_margin, 
         phone_x + phone_width - screen_margin, phone_y + phone_height - 40],
        radius=10,
        fill=(0, 0, 0, 255)
    )
    
    # Home button
    home_button_y = phone_y + phone_height - 30
    draw.ellipse(
        [phone_x + phone_width//2 - 15, home_button_y - 15,
         phone_x + phone_width//2 + 15, home_button_y + 15],
        fill=(200, 200, 200, 255)
    )
    
    # Add some tunnel/network lines
    for i in range(3):
        y = phone_y + 50 + i * 30
        draw.line([phone_x + 20, y, phone_x + phone_width - 20, y], 
                 fill=(0, 150, 255, 255), width=2)
    
    # Save the icon
    img.save('icon.png')
    print("Icon created: icon.png")

if __name__ == "__main__":
    try:
        create_icon()
    except ImportError:
        print("PIL (Pillow) not installed. Creating a simple text file instead.")
        with open('icon.png', 'w') as f:
            f.write("# This is a placeholder icon file")
        print("Placeholder icon file created: icon.png")
