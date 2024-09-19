import datetime
import PySimpleGUI as pg
import pyotp
import qrcode
import bcrypt
import re

def get_hashed_password(plain_text_password): # hashes password
    plain_text_password = plain_text_password
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())

def check_password(plain_text_password, hashed_password): # checks password against stored
    return bcrypt.checkpw(plain_text_password, hashed_password)

def keygen(key_input):
    key = key_input.upper()  # uppercase string from input box
    key = re.sub(r'[^a-zA-Z]', 'B', key)  # remove non-alpha characters

    if len(key) < 16:
        key = key.ljust(16, 'A')  # pad string with A's
    elif len(key) > 16: # cut string if too long for keygen
        key = key[-16:]

    return key # returns 16-character key string

def main():
    incorrect_guesses = 0 # incorrect guesses counter
    timeout_end = " "

    window_layout = [ # sets layout of elements in window
        [pg.Text("Please enter your password:",
                 font=("Arial", 15))],
        [pg.Input(key='-INPUT-')],
        [pg.Button("Submit", key='-SUBMIT-')],
        [pg.Button("Generate QR Code", key='-GEN-QR-CODE-')],
        [pg.Text(" ", key='-OUTPUT-')],
        [pg.Text("Make sure to enter your password before generating a QR code")],
        [pg.Text("-------------------")],
        [pg.Text("QR code button is for testing; real deployments would email")],
        [pg.Text("this as one-time use")]
    ]

    # initializes window with layout
    window = pg.Window("Password Authenticator", window_layout,
                       size=(400, 300),
                       element_justification="center")


    # runs the pysimplegui window
    while True:
        event, values = window.read()

        if event in (None, 'Exit'): # closes window
            break

        if event == '-SUBMIT-': # on submit button click
            if incorrect_guesses < 3: # brute force protection, only evaluates if incorrect guesses is less than 3
                check = values['-INPUT-'].encode('utf-8') # get byte string from input box

                # if you want to manually input a password into the secrets file, you
                # can comment out the line below and copy the output and skim the "b'" and "'"
                # from the beginning and end respectively

                # print(get_hashed_password(check))

                # read hashed password from file
                with open("secrets.txt", "r") as file: # open file, iterate through lines
                    for line in file:
                        new_check = line.strip().encode('utf-8') # strips/encodes password
                        try:
                            if check_password(check, new_check): # check if password matches stored hashes
                                window['-OUTPUT-'].update(" ") # clears error output label
                                test_otp = pyotp.totp.TOTP(keygen(values['-INPUT-'])) # gets auth code object

                                # For testing if OTP code associated with password is correct
                                # print(test_otp.now())

                                code = pg.popup_get_text("Enter your 2FA authenticator code") # popup prompt

                                if int(code) == int(test_otp.now()):
                                    pg.popup_ok("Authentication successful! :D")
                                else:
                                    pg.popup_ok("Authentication failed - please try again")
                                break
                            else: # incorrect password
                                window['-OUTPUT-'].update("Incorrect password!")
                                incorrect_guesses += 1

                        except ValueError: # sometimes throws if salt gets freaky, usually incorrect password
                            pass
            else: # if you have exceeded 3 incorrect guesses
                pg.popup_annoying("You have exceeded the maximum number of attempts. Please wait 2 minutes for new attempts to login.")
                if timeout_end == " ": # set timer if not already set
                    timeout_end = datetime.datetime.now() + datetime.timedelta(minutes=2) # sets time to +2 min from now

                if datetime.datetime.now() > timeout_end: # if timer is up
                    timeout_end = " " # set timer to nothing
                    incorrect_guesses = 0 # reset incorrect guesses
                else: # if timer is not up
                    window['-OUTPUT-'].update("Please wait before entering more passwords")

        # qr code generator
        if event == '-GEN-QR-CODE-':
            qr_key = keygen(values['-INPUT-']) # grabs key relative to password input

            uri = pyotp.totp.TOTP(qr_key).provisioning_uri(name="Authorized User",
                                                        issuer_name="Admin")
            qrcode.make(uri).save("qr.png")
            # qr popup
            pg.popup_no_buttons(title='Über uns', keep_on_top=True, image="qr.png")

if __name__ == '__main__':
    main()