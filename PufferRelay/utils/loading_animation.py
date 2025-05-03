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
    shutil,
    threading,
    os
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
    lightning_frames = ['⚡', '⚡']  # Simple lightning animation frames
    loading_text = "Loading"
    dots = ""
    position = 0
    direction = 1  # 1 for right, -1 for left
    
    # Clear screen and hide cursor
    sys.stdout.write("\033[?25l")  # Hide cursor
    sys.stdout.write("\033[2J")    # Clear screen
    sys.stdout.write("\033[H")     # Move to top
    
    def show_ready(quick_wins=False):
        """Show the Ready message in purple ASCII art or Quick Wins banner in yellow."""
        # Clear screen and show message
        sys.stdout.write("\033[2J")    # Clear screen
        sys.stdout.write("\033[H")     # Move to top
        sys.stdout.flush()             # Ensure screen is cleared
        time.sleep(0.1)                # Small delay to ensure clear
        
        if quick_wins:
            # Show Quick Wins banner in yellow ASCII art
            quick_wins_art = """
\033[33m
⚡ ⚡ ⚡ Quick Wins Mode ⚡ ⚡ ⚡

 ██████╗ ██╗   ██╗██╗ ██████╗██╗  ██╗    ██╗    ██╗██╗███╗   ██╗███████╗
██╔═══██╗██║   ██║██║██╔════╝██║ ██╔╝    ██║    ██║██║████╗  ██║██╔════╝
██║   ██║██║   ██║██║██║     █████╔╝     ██║ █╗ ██║██║██╔██╗ ██║███████╗
██║▄▄ ██║██║   ██║██║██║     ██╔═██╗     ██║███╗██║██║██║╚██╗██║╚════██║
╚██████╔╝╚██████╔╝██║╚██████╗██║  ██╗    ╚███╔███╔╝██║██║ ╚████║███████║
 ╚══▀▀═╝  ╚═════╝ ╚═╝ ╚═════╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝
\033[0m
"""
            print(quick_wins_art)
        else:
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
    
    def update_animation(quick_wins=False):
        """Update the animation frame."""
        nonlocal position, direction, dots
        
        # Calculate position
        position += direction
        if position >= width - 3:  # Animation width is 3
            direction = -1
        elif position <= 0:
            direction = 1
        
        # Update loading dots
        dots = "." * ((int(time.time() * 2) % 3) + 1)
        
        # Clear current line and print animation
        sys.stdout.write("\033[2K")  # Clear line
        sys.stdout.write("\033[H")   # Move to top
        
        if quick_wins:
            # Print lightning animation in yellow
            print("\033[33m" + f"{' ' * position}{lightning_frames[int(time.time() * 2) % 2]}" + "\033[0m")
        else:
            # Print fish animation in purple
            print("\033[35m" + f"{' ' * position}{fish_frames[int(time.time() * 2) % 2]}" + "\033[0m")
        
        print(f"{loading_text}{dots}")
        print("=" * width)
        
        sys.stdout.flush()
    
    return update_animation, show_ready 