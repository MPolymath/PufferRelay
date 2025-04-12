# Created by Massamba DIOUF
#
# This file is part of PufferRelay.
#
# PufferRelay is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PufferRelay is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PufferRelay. If not, see <http://www.gnu.org/licenses/>.
#
# Credits: Portions of this code were adapted from PCredz (https://github.com/lgandx/PCredz)
#         (c) Laurent Gaffie GNU General Public License v3.0.

from PufferRelay.core_imports import (
    sys,
    time,
    shutil
)

def get_terminal_width():
    """Get the current terminal width, with a fallback to 80 characters."""
    try:
        return shutil.get_terminal_size().columns
    except:
        return 80

def show_loading_animation():
    """
    Display a simple loading animation with a swimming fish.
    Returns a function to show the Ready message.
    """
    width = get_terminal_width()
    fish_frames = ['><>', '<><']  # Simple fish animation frames
    loading_text = "Loading"
    dots = ""
    position = 0
    direction = 1  # 1 for right, -1 for left
    
    # Clear screen and hide cursor
    sys.stdout.write("\033[?25l")  # Hide cursor
    sys.stdout.write("\033[2J")    # Clear screen
    sys.stdout.write("\033[H")     # Move to top
    
    def show_ready():
        """Show the Ready message in purple ASCII art."""
        # Clear screen and show Ready message
        sys.stdout.write("\033[2J")    # Clear screen
        sys.stdout.write("\033[H")     # Move to top
        sys.stdout.flush()             # Ensure screen is cleared
        time.sleep(0.1)                # Small delay to ensure clear
        
        # Show Ready message in purple ASCII art
        ready_art = """
\033[35m
██████╗ ███████╗ █████╗ ██████╗ ██╗   ██╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝
██████╔╝█████╗  ███████║██║  ██║ ╚████╔╝ 
██╔══██╗██╔══╝  ██╔══██║██║  ██║  ╚██╔╝  
██║  ██║███████╗██║  ██║██████╔╝   ██║   
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝    ╚═╝   
\033[0m
"""
        print(ready_art)
        sys.stdout.write("\033[?25h")  # Show cursor
        sys.stdout.flush()
    
    def update_animation():
        """Update the animation frame."""
        nonlocal position, direction, dots
        
        # Calculate fish position
        position += direction
        if position >= width - 3:  # Fish width is 3
            direction = -1
        elif position <= 0:
            direction = 1
        
        # Update loading dots
        dots = "." * ((int(time.time() * 2) % 3) + 1)
        
        # Clear current line and print animation
        sys.stdout.write("\033[2K")  # Clear line
        sys.stdout.write("\033[H")   # Move to top
        
        # Print three lines
        print(f"{' ' * position}{fish_frames[int(time.time() * 2) % 2]}")
        print(f"{loading_text}{dots}")
        print("=" * width)
        
        sys.stdout.flush()
    
    return update_animation, show_ready 