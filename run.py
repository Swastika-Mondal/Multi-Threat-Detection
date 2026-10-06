import pyautogui as pag
import os

pwd = f'{os.getcwd()}/ngrok'

pag.hotkey('win', 'r')
pag.sleep(1)
pag.write('cmd')
pag.press('enter')
pag.sleep(1)
pag.write('color 2')
pag.press('enter')
pag.typewrite(f'cd {pwd}')
pag.press('enter')
pag.typewrite(f'd:')
pag.press('enter')
pag.typewrite(f'ngrok http --config "{pwd}/config/ngrok.yml" 4747', interval=0.01)
pag.press('enter')
pag.hotkey('win', 'd')


pag.hotkey('win', 'r')
pag.sleep(1)
pag.write('cmd')
pag.press('enter')
pag.sleep(1)
pag.write('color 4')
pag.press('enter')
pag.typewrite(f'cd {os.getcwd()}')
pag.press('enter')
pag.typewrite(f'd:')
pag.press('enter')
pag.typewrite('python multi_spam_detection.py', interval=0.01)
pag.press('enter')