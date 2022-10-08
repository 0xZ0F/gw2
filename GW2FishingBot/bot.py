import os
import threading
import time
import keyboard
import pyautogui

IMAGE_ALERT = "Alert.png"
IMG_CAST = "CastIcon.png"
IMG_GREEN = "Green.png"
IMG_TRIM = "HoleTrim.png"
IMG_DEBUG = "DEBUG.png"

BUTTON_START = "F9"
BUTTON_PAUSE = "F10"
BUTTON_STOP = "F11"

BUTTON_CAST = "q"
BUTTON_RIGHT = "r"
BUTTON_LEFT = "e"

# Smaller range increases processing speed.
# Where to search for the alert symbol
# Starts at _START and goes to _START + _RANGE
ALERT_X_START = 1100
ALERT_X_RANGE = 300
ALERT_Y_START = 300
ALERT_Y_RANGE = 300

HOLE_X_START = 1100
HOLE_X_RANGE = 400
HOLE_Y_START = 1150
HOLE_Y_RANGE = 100

# Alert image color ranges
ALERT_R_MIN = 230
ALERT_R_MAX = 253
ALERT_G_MIN = 43
ALERT_G_MAX = 58
ALERT_B_MIN = 89
ALERT_B_MAX = 109


def QuitThread():
    while True:
        if keyboard.is_pressed(BUTTON_STOP):
            keyboard.release(BUTTON_LEFT)
            keyboard.release(BUTTON_RIGHT)
            print("+ Bot Terminated")
            os._exit(0)
        time.sleep(.025)
        continue


def Bot():
    global NUM_FISH_CAUGHT

    print("! Bot Started")

    while True:
        if STOP_BOT:
            return

        # Cast Line
        while True:
            if pyautogui.locateCenterOnScreen(IMG_CAST, confidence=.8) != None:
                print("+ Casting Line")
                keyboard.press_and_release("q")
                break
            time.sleep(.25)

        # Detect Alert
        print("- Waiting for alert...")
        while True:
            found = False
            img = pyautogui.screenshot(
                region=(ALERT_X_START, ALERT_Y_START, ALERT_X_RANGE, ALERT_Y_RANGE))
            img.save(IMG_DEBUG)

            width, height = img.size

            for x in range(2, width, 2):
                if found:
                    break
                for y in range(2, height, 2):
                    r, g, b = img.getpixel((x, y))
                    if r in range(ALERT_R_MIN, ALERT_R_MAX):
                        if g in range(ALERT_G_MIN, ALERT_G_MAX):
                            if b in range(ALERT_B_MIN, ALERT_B_MAX):
                                found = True
                                break
            if found:
                print("! Fish Alert !")
                keyboard.press_and_release(BUTTON_CAST)
                break
            time.sleep(.2)

        # Handle Catching Fish:
        while True:
            holeLoc = pyautogui.locateCenterOnScreen(
                IMG_TRIM, region=(HOLE_X_START, HOLE_Y_START, HOLE_X_RANGE, HOLE_Y_RANGE), confidence=.65)

            IMG_GREENLoc = pyautogui.locateCenterOnScreen(
                IMG_GREEN, region=(HOLE_X_START, HOLE_Y_START, HOLE_X_RANGE, HOLE_Y_RANGE), confidence=.8)

            if IMG_GREENLoc != None:
                if holeLoc != None:
                    if(holeLoc.x < IMG_GREENLoc.x):
                        keyboard.press(BUTTON_RIGHT)
                        keyboard.release(BUTTON_LEFT)
                    elif(holeLoc.x > IMG_GREENLoc.x):
                        keyboard.press(BUTTON_LEFT)
                        keyboard.release(BUTTON_RIGHT)
                    else:
                        keyboard.release(BUTTON_LEFT)
                        keyboard.release(BUTTON_RIGHT)
            elif pyautogui.locateCenterOnScreen(IMG_CAST, confidence=.8) != None:
                # Fishing Over
                keyboard.release(BUTTON_LEFT)
                keyboard.release(BUTTON_RIGHT)
                NUM_FISH_CAUGHT += 1
                print("+ Estimated total fish caught:", NUM_FISH_CAUGHT)
                break


def main():
    # Uncomment this line to show cursor pos
    pyautogui.displayMousePosition()

    print("\t-------------------------")
    print("\tGW2 Fishing Bot - By Z0F")
    print("\t1) Set your camera height to the max in the game settings.")
    print("\t2) Zoom into first person, then zoom one notch out from your character.")
    print("\t3) Focus GW2 Window")
    print(f"\t4) Press {BUTTON_START} to start bot.")
    print("\tNote: The bot will focus on the game to press buttons.")
    print(f"\t- Press {BUTTON_PAUSE} to pause bot.")
    print(f"\t- Press {BUTTON_STOP} to stop bot.")
    print("\t-------------------------")

    global STOP_BOT
    global NUM_FISH_CAUGHT
    STOP_BOT = False
    NUM_FISH_CAUGHT = 0

    while not keyboard.is_pressed(BUTTON_START):
        continue

    botThread = threading.Thread(target=Bot)
    botThread.start()

    quitThread = threading.Thread(target=QuitThread)
    quitThread.daemon = True
    quitThread.start()

    while True:
        if keyboard.is_pressed(BUTTON_PAUSE):
            STOP_BOT = not STOP_BOT
            print("- Pause:", STOP_BOT)

            if STOP_BOT and botThread.is_alive:
                print("- Pausing Bot")
                botThread.join()
            elif not STOP_BOT:
                botThread = threading.Thread(target=Bot)
                botThread.start()
            time.sleep(.25)

        time.sleep(.025)
        continue


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
    except FileNotFoundError as err:
        print(f"File not found: {err}")
