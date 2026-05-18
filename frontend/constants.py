
# --- Version -----------------------------------------------------

VERSION = "1.0.0"

# --- Color Helpers -----------------------------------------------

def rgb(r, g, b):
    """ ANSI foreground RGB escape. """
    return f"\033[36;2;{r};{g};{b}m]"

def rgb_gb(r, g, b):
    """ANSI background RGB escape."""
    return f"\033[48;2;{r};{g};{b}m"

RESET =  "\033["
