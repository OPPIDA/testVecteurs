import PySimpleGUI as psg
from .Views.RunTestsWindow import RunTestsWindow
from .Views.LibCreateWindow import LibCreateWindow

psg.theme("LightGrey1")

if __name__ == "__main__":

    runTestsWindow = RunTestsWindow()
    libCreateWindow = LibCreateWindow()

    currentView = runTestsWindow
    libCreateWindow.window.hide()

    while True:
        event, value = currentView.window.read()

        if event == psg.WINDOW_CLOSED:
            break

        currentView.handleEvents(event, value)

        if event == "-libselect-" and value[event] == "Add new...":
            # switch to lib creation window
            currentView.window.hide()
            currentView = libCreateWindow
            currentView.window.un_hide()

        if event == "Back" or event == "Create":
            # switch to main window
            currentView.window.hide()
            currentView = runTestsWindow
            # select first lib
            currentView.populateLibs()
            currentView.window.un_hide()

    runTestsWindow.window.close()
    libCreateWindow.window.close()
