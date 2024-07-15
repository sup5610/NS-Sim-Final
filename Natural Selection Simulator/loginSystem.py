# -*- coding: utf-8 -*-
"""
Created on Wed Mar  9 00:27:45 2022

@author: Marco

Supporting scripts required: dbCommands.py, databaseCreator.py, database_commands.sql, database_creator.sql

Libraries required: tkinter, sys, time, numpy, sqlite3, hashlib, secrets, pandas, os, random, matplotlib, socket,
json, math, uuid, PIL, datetime, clipboard
"""

import tkinter as tk, sys, time, numpy as np, sqlite3, hashlib, secrets, pandas, os, random, matplotlib.pyplot as plt, socket, json, math, uuid, clipboard
from tkinter import font as tkfont
from tkinter import ttk 
from PIL import ImageTk, Image
from datetime import datetime
from dbCommands import *
from databaseCreator import *

# colours
BGONE = "#212529"
BGTWO = "#6C757C"
BGTHREE = "#CCC5B9"
FGONE = "#DEE2E6"
FGTWO = "#EAE0CC"
FGTHREE = "#EAE0CC"
myOrange = u"#ff7f0e"
myBlue = u"#1f77b4"

# GUI variables
global is_maximised
is_maximised = False

# socket creation
socket.setdefaulttimeout(1)

host, port = "127.0.0.1", 64738
global sock
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

global connected
connected = False
connectionAttempts = 0
while connected == False and connectionAttempts < 3: # required connection attempts
    try:
        sock.connect((host, port))
    except:
        print("Connection not open on from Unity")
        connectionAttempts += 1
        time.sleep(1)
    else:
        connected = True
        
# database and file management
currentFolder = os.getcwd()

databasePath = currentFolder + r"\natural_selection.db"
databaseCreatorSQL = currentFolder + r"\database_creator.sql"
databaseCommandsSQL = currentFolder + r"\database_commands.sql"

if (not os.path.isfile(databasePath)):
    CreateDatabase(databasePath, databaseCreatorSQL)
    CreateDefaultUsers(databasePath)


class Animal: # class defined
    def __init__(self, attack, maxHealth, speed, viewDistance, isMale, guid, isProgenitor):
        self.attack = attack
        self.maxHealth = maxHealth
        self.speed = speed
        self.viewDistance = viewDistance
        self.isMale = isMale
        self.guid = guid
        self.isProgenitor = isProgenitor

class log_in():
    def __init__(self, master):
        master.attributes("-topmost", True)
        master.overrideredirect(True)

        normal_font = tkfont.Font(family = "Verdana", size = 10)
        bold_font = tkfont.Font(family = "Verdana", size = 9, weight = "bold")

        self.root = master # self.root variable created to destroy window
        self.details = ["", ""] # username and password inputs
        self.x = [] # all x values of cursor where an event occurs
        self.y = [] # all y values of cursor where an event occurs
        self.username_accepted = False
        self.password_accepted = False
        self.details_accpted = False
        
        self.pre_salt = "" # pre salt for password
        self.post_salt = "" # post salt for password
        self.salted_password = "" # stores salted entered password
        self.hashed_password = "" # stored hashed salted password
        self.stored_data = ("", "")
        
        master.bind("<KeyPress>", self.store)
        master.bind("<Button-1>", self.store)
        master.bind("<Button-2>", self.store)


        init_window(self, master, 150, 75)


        self.pad2 = tk.Label(self.canvas)
        self.pad2.grid(row = 0, column = 0, columnspan = 5)
        self.pad2.config(bg = BGTWO)

        self.pad3 = tk.Label(self.canvas)
        self.pad3.grid(row = 0, column = 0, rowspan = 5)
        self.pad3.config(bg = BGTWO)

        # misc. label
        self.label1 = tk.Label(self.canvas)
        self.label1.grid(row = 1, column = 1)
        self.label1.config(text = "Log in", font = bold_font, bg = BGTWO, fg = FGONE)       
        
        # username label and entry
        self.username_label = tk.Label(self.canvas)
        self.username_label.grid(row = 2, column = 1)
        self.username_label.config(text = "Username", font = normal_font, bg = BGTWO, fg = FGONE)
        self.username_entry = tk.Entry(self.canvas)
        self.username_entry.grid(row = 2, column = 2)
        self.username_entry.config()
        self.username_entry.focus_set()

        # password label and entry
        self.password_label = tk.Label(self.canvas)
        self.password_label.grid(row = 3, column = 1)
        self.password_label.config(text = "Password", font = normal_font, bg = BGTWO, fg = FGONE)
        self.password_entry = tk.Entry(self.canvas)
        self.password_entry.grid(row = 3, column = 2)
        self.password_entry.config(show = "●")
        self.i = tk.IntVar()
        self.show_password = tk.Checkbutton(self.canvas)
        self.show_password.grid(row = 3, column = 3)
        self.show_password.config(bg = BGTWO, fg = FGONE, activebackground = BGTWO, activeforeground = FGONE, text = "show password", variable = self.i)
        self.show_password.bind("<Button-1>", self.hide_show)

        # button to enter
        self.enter_button = tk.Button(self.canvas)
        self.enter_button.grid(row = 3, column = 4)
        self.enter_button.config(text = "Log in", command = lambda : self.validate(), relief = tk.GROOVE, bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO)
        self.enter_button.bind("<Enter>", self.enter_enter)
        self.enter_button.bind("<Leave>", self.enter_leave)
        
        # label to feedback to user
        self.label2 = tk.Label(self.canvas)
        self.label2.grid(row = 4, column = 2)
        self.label2.config(font = bold_font, bg = BGTWO, fg = FGONE)

        self.clock_function(self.canvas)

    ###########################################################################################################################
    def clock_function(self, window):
        # clock
        self.ct = time.strftime("%H:%M:%S")
        self.clock_frame = tk.Frame(window)
        self.clock_frame.grid(row = 0, column = 5)
        self.clock_frame.config(bg = FGONE, bd = 1)
        self.clock_display = tk.Label(self.clock_frame)
        self.clock_display.grid(row = 0, column = 0)
        self.clock_display.config(text = self.ct, width = 6, bg = BGTWO, fg = FGONE)

        self.ct = time.strftime("%H:%M:%S")
        self.clock_display["text"] = self.ct
        window.after(1000, lambda : self.clock_function(window))
    ###########################################################################################################################
    # hide and show password in entry
    def hide_show(self, event):
        if self.i.get() == 0:
            self.password_entry.config(show = "")
        else:
            self.password_entry.config(show = "●")

    # clear the userename and password entries
    def clear_entries(self):
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.details = ["", ""]

    # function stores data
    def store(self, event):
        self.details[0] = self.username_entry.get()
        self.details[1] = self.password_entry.get()
        print(self.details)
        print(event)
        self.x.append(event.x)
        self.y.append(event.y)
        
        if event.keycode == 13: # enter
            self.validate()
        elif event.keycode == 17: # ctrl
            self.xy()
            
    # function prints mean x and y values of cursor
    def xy(self):
        print("Mean X: " + str(np.mean(self.x, dtype = "float64")))
        print("Mean Y: " + str(np.mean(self.y, dtype = "float64")))

    ###########################################################################################################################
    # functions hash entered password
    def saltify(self):
        self.pre_salt = self.stored_data[3]
        self.post_salt = self.stored_data[4]
        self.salted_password = self.pre_salt + self.details[1] + self.post_salt
        
    def hashify(self):
        self.hashed_password = hashlib.sha512(self.salted_password.encode()).hexdigest()
        
    def process_password(self):
        self.saltify()
        self.hashify()
    ###########################################################################################################################
    # functions validate entered username and password
    def download_data(self):
        con, cur = connectDB()
        
        cur.execute("SELECT * FROM login WHERE username=:usn", {"usn":self.details[0]})
        self.stored_data = cur.fetchone()
        
        con.commit()
        con.close()

    ###########################################################################################################################
    def validate(self):
        self.download_data()
        self.validate_username()
        if self.username_accepeted == True:
            self.validate_password()
            if self.password_accepeted == True:
                self.details_accepeted()
            else:
                self.password_rejected()    
        else:
            self.username_rejected()
        
        
        self.username_entry.focus_set()   
        
    def validate_username(self):
        if self.stored_data == None:
            self.username_accepeted = False
            self.password_accepeted = False
        else:
            self.username_accepeted = True           

    def username_rejected(self):
        self.clear_entries()
        self.label2["text"] = "Invalid Details"
        self.username_accepeted = False
        self.password_accepeted = False

    def validate_password(self):
        if self.stored_data == None:
            self.username_accepeted = False
            self.password_accepeted = False
        else:
            self.process_password()
            if self.hashed_password == self.stored_data[2]:
                self.password_accepeted = True
            else:
                self.password_accepeted = False

    def password_rejected(self):
        self.clear_entries()
        self.label2["text"] = "Invalid Details"
        self.username_accepeted = False
        self.password_accepeted = False

    def details_accepeted(self):
        self.label2["text"] = "Access Granted"
        self.details_accepeted = True

        if self.stored_data[5] == 1: # if admin
            self.root.destroy()
            a = tk.Tk()
            self.admin_session = admin(a, self.details[0]) # starts admin session
            a.mainloop()
        else:
            self.root.destroy()
            u = tk.Tk()
            self.user_session = user(u, self.details[0], True) # self.details[0] is the username, starts user session
            u.mainloop()

    def enter_enter(self, event):
        self.enter_button.config(bg = BGONE, fg = FGONE)
    def enter_leave(self, event):
        self.enter_button.config(bg = BGTWO, fg = FGONE)

class admin():
    def __init__(self, master, user):
        master.attributes("-topmost", True)
        master.overrideredirect(True)
        self.loggedInUsn = user

        self.root = master
        init_window(self, master, 150, 75)
        

        self.instruct_label = tk.Label(self.canvas)
        self.instruct_label.grid(row = 1, column = 1)
        self.instruct_label.config(text = "Admin options:", bg = BGTWO, fg = FGONE)

        self.new_user_button = tk.Button(self.canvas, bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO)
        self.new_user_button.grid(row = 3, column = 1)
        self.new_user_button.config(text = "Create New User", width = 20, command = lambda : self.create_new_user_window())
    
        self.edit_users_button = tk.Button(self.canvas, bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO)
        self.edit_users_button.grid(row = 5, column = 1)
        self.edit_users_button.config(text = "Edit User Details", width = 20, command = lambda : self.create_edit_users_window())

        
        self.logOutBtn = tk.Button(self.canvas, bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO)
        self.logOutBtn.config(text = "Log Out", bg = BGONE, fg = FGONE, activebackground = BGTWO, activeforeground = BGONE, command = lambda : self.LogOut())
        self.logOutBtn.grid(row = 7, column = 1)
        self.logOutBtn.bind("<Enter>", self.logOutEnter)
        self.logOutBtn.bind("<Leave>", self.logOutLeave)

        self.placeholder1 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder1.grid(row= 0, column = 0)
        self.placeholder2 = tk.Label(self.canvas, bg = BGTWO)
        self.placeholder2.grid(row= 2, column = 0)
        self.placeholder3 = tk.Label(self.canvas, bg = BGTWO)
        self.placeholder3.grid(row = 4, column = 0)
        self.placeholder4 = tk.Label(self.canvas, bg = BGTWO)
        self.placeholder4.grid(row = 6, column = 0)
        self.placeholder5= tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder5.grid(row = 8, column = 2) 
        
    def LogOut(self):
        self.root.destroy()
        rot = tk.Tk()
        log_in(rot)
        rot.mainloop()

    def create_new_user_window(self):
        self.root.destroy()
        rot = tk.Tk()
        new_user(rot, self.loggedInUsn)
        rot.mainloop()

    def create_edit_users_window(self):
        self.root.destroy()
        rot = tk.Tk()
        edit_users(rot, self.loggedInUsn)
        rot.mainloop()
    ########################################################################################################################### 
    def enter_enter(self, event):
        self.enter_button.config(bg = BGTWO, fg = FGONE)
    def enter_leave(self, event):
        self.enter_button.config(bg = BGONE)

    def logOutEnter(self, event):
        self.logOutBtn.config(bg = BGTWO)

    def logOutLeave(self, event):
        self.logOutBtn.config(bg = BGONE)

class new_user():
    def __init__(self, master, user):
        master.attributes("-topmost", True)
        master.overrideredirect(True)
        self.loggedInUsn = user

        self.root = master
        self.details = ["", "", ""]
        self.x = []
        self.y = []
        self.options = ["user", "admin"]

        master.bind("<KeyPress>", self.store)
        master.bind("<Button-1>", self.store)
        master.bind("<Button-2>", self.store)


        init_window(self, master, 150, 75)


        self.username_label = tk.Label(self.canvas)
        self.username_label.grid(row = 0, column = 0)
        self.username_label.config(text = "New Username", bg = BGTWO, fg = FGONE)
        self.new_username = tk.Entry(self.canvas)
        self.new_username.grid(row = 0, column = 1)
        self.new_username.config()
        self.new_username.focus_set()

        self.password_label = tk.Label(self.canvas)
        self.password_label.grid(row = 1, column = 0)
        self.password_label.config(text = "New Password", bg = BGTWO, fg = FGONE)
        self.new_password = tk.Entry(self.canvas)
        self.new_password.grid(row = 1, column = 1)
        self.new_password.config(show = "●")

        self.password_conf_label = tk.Label(self.canvas)
        self.password_conf_label.grid(row = 2, column = 0)
        self.password_conf_label.config(text = "Confirm Password", bg = BGTWO, fg = FGONE)
        self.password_conf = tk.Entry(self.canvas)
        self.password_conf.grid(row = 2, column = 1)
        self.password_conf.config(show = "●")

        self.permissions_label = tk.Label(self.canvas)
        self.permissions_label.grid(row = 3, column = 0)
        self.permissions_label.config(text = "Permissions:", bg = BGTWO, fg = FGONE)

        self.string_var = tk.StringVar(self.canvas)
        self.string_var.set("user")
        self.admin_or_not = tk.OptionMenu(self.canvas, self.string_var, *self.options)
        self.admin_or_not.grid(row = 3, column = 1)
        self.admin_or_not.config(bg = BGTWO, fg = FGONE, bd = 0)
        self.admin_or_not.config(bd = 0, bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO)
        self.admin_or_not["menu"].config(bd = 0, bg = BGTWO, fg = FGTWO, activebackground = BGONE, activeforeground = FGTWO, selectcolor = BGTHREE)

        self.enter_button = tk.Button(self.canvas)
        self.enter_button.grid(row = 4, column = 0)
        self.enter_button.config(text = "Create", command = self.add_user, bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO)

        self.feedback_label = tk.Label(self.canvas)
        self.feedback_label.grid(row = 4, column = 1)
        self.feedback_label.config(width = 20, justify = tk.RIGHT, bg = BGTWO, fg = FGONE)
        # self.feedback_label.config(font = bold_font, width = 20, justify = tk.RIGHT, bg = BGTWO, fg = FGONE)

        self.back_button = tk.Button(self.canvas)
        self.back_button.grid(row = 4, column = 3)
        self.back_button.config(text = "Back", bg = BGONE, fg = FGONE, activebackground = BGTWO, activeforeground = BGONE, command = lambda : self.back_to_admin())
        self.back_button.bind("<Enter>", self.back_enter)
        self.back_button.bind("<Leave>", self.back_leave)
        
        self.placeholder1 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder1.grid(row = 5, column = 0)

        self.clock_function(self.canvas)
    ###########################################################################################################################
    def clock_function(self, window):
        # clock
        self.ct = time.strftime("%H:%M:%S")
        self.clock_frame = tk.Frame(window)
        self.clock_frame.grid(row = 0, column = 5)
        self.clock_frame.config(bg = FGONE, bd = 1)
        self.clock_display = tk.Label(self.clock_frame)
        self.clock_display.grid(row = 0, column = 0)
        self.clock_display.config(text = self.ct, width = 6, bg = BGTWO, fg = FGONE)

        self.ct = time.strftime("%H:%M:%S")
        self.clock_display["text"] = self.ct
        window.after(1000, lambda : self.clock_function(window))
        # if (self.feedback_label["text"] != ""): # test for autoclear label. sloppy
        #     self.feedback_label["text"] = ""
    ########################################################################################################################### 
    def validate_username(self):

        con, cur = connectDB()
        cur.execute("SELECT USERNAME FROM login WHERE USERNAME =:usn", {"usn": self.details[0]})
        self.return_user = cur.fetchall()

        con.commit()    
        con.close()

        if len(self.return_user) == 0 and self.details[0] != "":
            self.valid_username = True
        else:
            self.valid_username = False

    def password_confirmed(self):
        if self.details[1] == self.details[2]:
            self.passwords_the_same = True
        else:
            self.passwords_the_same = False

    def encrypt_password(self):
        self.pre_salt = secrets.token_hex(16)
        self.post_salt = secrets.token_hex(16)
        self.new_salted_password = self.pre_salt + self.details[1] + self.post_salt
        self.new_hashed_password = hashlib.sha512(self.new_salted_password.encode()).hexdigest()

        self.commit_details()

    def commit_details(self):
        if self.string_var.get() == "user":
            self.is_admin = 0
        elif self.string_var.get() == "admin":
            self.is_admin = 1
        self.insert_details = (self.details[0], self.new_hashed_password, self.pre_salt, self.post_salt, self.is_admin)
        
        con, cur = connectDB()

        cur.execute("INSERT INTO login (USERNAME, HASHED_PASS, PRE_SALT, POST_SALT, ADMIN) VALUES (?, ?, ?, ?, ?)", self.insert_details)

        con.commit()
        con.close()

        self.feedback_label["text"] = "Account Created"
        print("committed")
        print(self.details)
        self.new_username.delete(0, tk.END)
        self.new_password.delete(0, tk.END)
        self.password_conf.delete(0, tk.END)
        self.details = ["", "", ""]

    def add_user(self):
        self.validate_username()
        if self.valid_username == False:
            print("invalid username")
            if self.details[0] == "":
                self.feedback_label["text"] = "Invalid Username"
            else:
                self.feedback_label["text"] = "Username already in use"
            self.new_username.delete(0, tk.END)
            self.new_password.delete(0, tk.END)
            self.password_conf.delete(0, tk.END)
            self.details = ["", "", ""]
        elif self.valid_username == True:
            print("valid username")
            self.password_confirmed()
            if self.passwords_the_same == False:
                print("passwords not matched")
                self.new_password.focus_set()
                self.new_password.delete(0, tk.END)
                self.password_conf.delete(0, tk.END)
                self.details[1] = ""
                self.details[2] = ""
                self.feedback_label["text"] = "Passwords do not match"
            elif self.passwords_the_same == True:
                print("passwords matched")
                self.feedback_label["text"] = ""
                self.encrypt_password()

    def back_to_admin(self):
        self.root.destroy()
        a = tk.Tk()
        self.admin_session = admin(a, self.loggedInUsn) # starts admin session
        a.mainloop()
        
    def store(self, event):
        self.details[0] = self.new_username.get()
        self.details[1] = self.new_password.get()
        self.details[2] = self.password_conf.get()
        print(self.details)
        print(event)
        self.x.append(event.x)
        self.y.append(event.y)

        if event.keycode == 13: # enter
            self.add_user()
        elif event.keycode == 17: # ctrl
            self.xy()

    def xy(self):
        print("Mean X: " + str(np.mean(self.x, dtype = "float64")))
        print("Mean Y: " + str(np.mean(self.y, dtype = "float64")))
    ###########################################################################################################################
    def enter_enter(self, event):
        self.enter_button.config(bg = BGTWO, fg = FGTWO)
    def enter_leave(self, event):
        self.enter_button.config(bg = BGONE)

    def back_enter(self, event):
        self.back_button.config(bg = BGTWO)
    def back_leave(self, event):
        self.back_button.config(bg = BGONE)

class edit_users():
    def __init__(self, master, user):
        master.attributes("-topmost", True)
        master.overrideredirect(True)
        self.loggedInUsn = user

        master.bind("<KeyPress>", self.filter)

        self.root = master

        self.con, self.cur = connectDB() # fetches all usernames of users
        # self.sql = "SELECT USERNAME FROM login WHERE ADMIN = 0"
        self.sql = "SELECT USERNAME FROM login" # gets all users includin admins
        self.cur.execute(self.sql)
        self.usernames = self.cur.fetchall()
        self.con.commit()
        self.con.close()

        init_window(self, master, 150, 75)


        self.filter_label = tk.Label(self.canvas)
        self.filter_label.grid(row = 0, column = 0)
        self.filter_label.config(text = "Filter:", bg = BGTWO, fg = FGONE)
        self.filter_entry = tk.Entry(self.canvas)
        self.filter_entry.grid(row = 0, column = 1)
        self.filter_button = tk.Button(self.canvas)
        self.filter_button.grid(row = 0, column = 2)
        self.filter_button.config(text = "Filter", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.filter(event = None))

        self.options = ["select user"]
        for i in range(len(self.usernames)):
            self.options.append(self.usernames[i][0])

        self.string_var = tk.StringVar(self.canvas)
        self.string_var.set("select user")
        self.user_select = tk.OptionMenu(self.canvas, self.string_var, *self.options)
        self.user_select.grid(row = 0, column = 0)
        self.user_select.config(width = 15, bd = 0, bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO)
        self.user_select["menu"].config(bd = 0, bg = BGTWO, fg = FGTWO, activebackground = BGONE, activeforeground = FGTWO, selectcolor = BGTHREE)


        self.delete_button = tk.Button(self.canvas)
        self.delete_button.grid(row = 4, column = 0)
        self.delete_button.config(text = "Delete User", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.delete_user())

        self.new_username_label = tk.Label(self.canvas)
        self.new_username_label.grid(row = 1, column = 0)
        self.new_username_label.config(text = "New Username", bg = BGTWO, fg = FGONE)
        self.new_username_entry = tk.Entry(self.canvas)
        self.new_username_entry.grid(row = 1, column = 1)
        self.new_username_entry.config()
        self.change_username_button = tk.Button(self.canvas)
        self.change_username_button.grid(row = 1, column = 2)
        self.change_username_button.config(text = "Change Username", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.change_username())

        self.new_password_label = tk.Label(self.canvas)
        self.new_password_label.grid(row = 2, column = 0)
        self.new_password_label.config(text = "New Password", bg = BGTWO, fg = FGONE)
        self.new_password_entry = tk.Entry(self.canvas)
        self.new_password_entry.grid(row = 2, column = 1)
        self.new_password_entry.config()
        self.new_password_button = tk.Button(self.canvas)
        self.new_password_button.grid(row = 2, column = 2)
        self.new_password_button.config(text = "Change Password", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.change_password())

        self.back_button = tk.Button(self.canvas)
        self.back_button.grid(row = 4, column = 2)
        self.back_button.config(text = "Back", bg = BGONE, fg = FGONE, activebackground = BGTWO, activeforeground = BGONE, command = lambda : self.back_to_admin())
        self.back_button.bind("<Enter>", self.back_enter)
        self.back_button.bind("<Leave>", self.back_leave)

        self.indicatorLbl = tk.Label(self.canvas, bg = BGTWO, fg = FGONE, width = 25)
        self.indicatorLbl.grid(row = 3, column = 1)

        self.placeholder1 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder1.grid(row = 5, column = 0)

        self.clock_function(self.canvas)
    ###########################################################################################################################
    def clock_function(self, window):
        # clock
        self.ct = time.strftime("%H:%M:%S")
        self.clock_frame = tk.Frame(window)
        self.clock_frame.grid(row = 0, column = 5)
        self.clock_frame.config(bg = FGONE, bd = 1)
        self.clock_display = tk.Label(self.clock_frame)
        self.clock_display.grid(row = 0, column = 0)
        self.clock_display.config(text = self.ct, width = 6, bg = BGTWO, fg = FGONE)

        self.ct = time.strftime("%H:%M:%S")
        self.clock_display["text"] = self.ct
        window.after(1000, lambda : self.clock_function(window))
    ###########################################################################################################################
    def filter(self, event):
        self.filter_string = ""
        self.filter_string = self.filter_entry.get()

        self.con, self.cur = connectDB()
        self.cur.execute("SELECT USERNAME FROM login WHERE USERNAME LIKE :filter", {"filter": "%" + self.filter_string + "%"})
        self.filtered_usernames = self.cur.fetchall()
        self.con.commit()
        self.con.close()

        if event == None or event.keycode == 13:
            self.options = ["select user"]
            self.user_select["menu"].delete(0, tk.END)
            self.user_select["menu"].add_command(label = "select user", command = tk._setit(self.string_var, self.options[0]))
            self.string_var.set("select user")

            for choice in self.filtered_usernames:
                self.options.append(choice[0])
                self.user_select["menu"].add_command(label = choice, command = tk._setit(self.string_var, choice[0]))

    def delete_user(self):
        self.selected = self.string_var.get()

        if self.selected == "select user":
            print("pass")
        else:
            self.con, self.cur = connectDB()
        
            self.cur.execute("SELECT USER_ID FROM login WHERE USERNAME =:sel", {"sel": self.selected})
            userId = self.cur.fetchone()[0]

            self.cur.execute("DELETE FROM login WHERE USERNAME =:sel", {"sel": self.selected})

            self.cur.execute("SELECT RUN_ID FROM results WHERE RUNNER_ID =:runnerId", {"runnerId": userId})
            runIds = self.cur.fetchall()

            for i in runIds:
                self.cur.execute("DELETE FROM results WHERE RUNNER_ID =:userId", {"userId": userId})
                self.cur.execute("DELETE FROM wolf_results WHERE RUN_ID =:runId", {"runId": i[0]})
                self.cur.execute("DELETE FROM deer_results WHERE RUN_ID =:runId", {"runId": i[0]})


            self.con.commit()
            self.con.close()
            print("user deleted")
            self.indicatorLbl["text"] = "User Deleted"

            self.string_var.set("select user")
            self.filter_entry.delete(0, tk.END)
            self.new_username_entry.delete(0, tk.END)
            self.new_password_entry.delete(0, tk.END)

            self.filter(event = None)

    def change_username(self):
        self.selected = self.string_var.get()
        self.new_username = self.new_username_entry.get()
        self.valid = False

        if self.new_username == "":
            self.valid = False
            print("username cannot be empty")
            self.indicatorLbl["text"] = "Username cannot be empty"
        else:
            self.con, self.cur = connectDB()
            self.cur.execute("SELECT USERNAME FROM login WHERE USERNAME =:usn", {"usn": self.new_username})
            self.return_username = self.cur.fetchall()
            self.con.commit()
            self.con.close()

            if len(self.return_username) == 0:
                self.valid = True
                print("valid")
            else:
                self.valid = False
                print("username already exists")
                self.indicatorLbl["text"] = "Username already exists"

        if self.selected == "select user":
            print("pass")
        else:
            if self.valid == True:

                self.con, self.cur = connectDB()
                self.cur.execute("UPDATE login SET USERNAME =:new_usn WHERE USERNAME =:sel", {"new_usn": self.new_username, "sel": self.selected})
                self.con.commit()
                self.con.close()
                print("username changed")
                self.indicatorLbl["text"] = "Username Changed"

                self.string_var.set("select user")
                self.filter_entry.delete(0, tk.END)
                self.new_username_entry.delete(0, tk.END)
                self.new_password_entry.delete(0, tk.END)
                self.filter(event = None)

    def change_password(self):
        self.selected = self.string_var.get()
        self.new_password = self.new_password_entry.get()

        self.pre_salt = secrets.token_hex(16)
        self.post_salt = secrets.token_hex(16)
        self.salted_password = self.pre_salt + self.new_password + self.post_salt
        self.hashed_password = hashlib.sha512(self.salted_password.encode()).hexdigest()

        if self.selected == "select user":
            print("pass")
            self.indicatorLbl["text"] = "No User Selected"
        else:
            self.con, self.cur = connectDB()
            self.cur.execute("UPDATE login SET HASHED_PASS =:hashed, PRE_SALT =:pre_salt, POST_SALT =:post_salt WHERE USERNAME =:sel", {"hashed":self.hashed_password, "pre_salt": self.pre_salt, "post_salt": self.post_salt, "sel": self.selected})

            self.con.commit()
            self.con.close()
            print("password changed")
            self.indicatorLbl["text"] = "Password Changed"

            self.string_var.set("select user")

    def back_to_admin(self):
        self.root.destroy()
        a = tk.Tk()
        self.admin_session = admin(a, self.loggedInUsn) # starts admin session
        a.mainloop()
   
    def enter_enter(self, event):
        self.enter_button.config(bg = BGTWO, fg = FGTWO)
    def enter_leave(self, event):
        self.enter_button.config(bg = BGONE)

    def back_enter(self, event):
        self.back_button.config(bg = BGTWO)
    def back_leave(self, event):
        self.back_button.config(bg = BGONE)

class user():
    def __init__(self, master, user, hasResults):
        master.attributes("-topmost", True)
        master.overrideredirect(True)
        init_window(self, master, 150, 75)
        self.loggedInUsn = user

        self.root = master

        self.start_simulation_button = tk.Button(self.canvas)
        self.start_simulation_button.config(text = "Start Simulation", bg = BGTWO, fg = FGONE, width = 15, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.start_simulation_window())
        self.start_simulation_button.grid(row = 1, column = 1)

        self.review_results_button = tk.Button(self.canvas)
        self.review_results_button.config(text = "Review Results", bg = BGTWO, fg = FGONE, width = 15, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.review_results_window())
        self.review_results_button.grid(row = 3, column = 1)

        self.logOutBtn = tk.Button(self.canvas, bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO)
        self.logOutBtn.config(text = "Log Out", bg = BGONE, fg = FGONE, activebackground = BGTWO, activeforeground = BGONE, command = lambda : self.LogOut())
        self.logOutBtn.grid(row = 5, column = 1)
        self.logOutBtn.bind("<Enter>", self.logOutEnter)
        self.logOutBtn.bind("<Leave>", self.logOutLeave)

        self.placeholder1 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder1.grid(row = 0, column = 0)
        self.placeholder2 = tk.Label(self.canvas, bg = BGTWO)
        self.placeholder2.grid(row = 2, column = 0)
        self.placeholder3 = tk.Label(self.canvas, bg = BGTWO)
        self.placeholder3.grid(row = 4, column = 0)
        self.placeholder4 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder4.grid(row = 6, column = 2)

        self.requirementsLbl = tk.Label(self.canvas, bg = BGTWO, fg = FGONE, width = 25)
        self.requirementsLbl.grid(row = 0, column = 1)


        if (not hasResults):
            self.requirementsLbl["text"] = "Simulation Results Required"


    def start_simulation_window(self):
        if (not connected):
            self.requirementsLbl["text"] = "Unity Connection Required"
        else:
            self.root.destroy()
            rot = tk.Tk()
            ChooseSimulationType(rot, self.loggedInUsn)
            rot.mainloop()
    
    def review_results_window(self): # code to receive simulation result data
        self.root.destroy()
        rot = tk.Tk()
        ReviewResults(rot, self.loggedInUsn)
        rot.mainloop()

    def LogOut(self):
        self.root.destroy()
        rot = tk.Tk()
        log_in(rot)
        rot.mainloop()

    def logOutEnter(self, event):
        self.logOutBtn.config(bg = BGTWO)

    def logOutLeave(self, event):
        self.logOutBtn.config(bg = BGONE)
  
class ChooseSimulationType():
    def __init__(self, master, user):
        master.attributes("-topmost", True)
        master.overrideredirect(True)
        init_window(self, master, 150, 75)
        self.loggedInUsn = user

        self.root = master

        self.random_label = tk.Label(self.canvas)
        self.random_label.config(text = "Random Starting Population", bg = BGTWO, fg = FGONE)
        self.random_label.grid(row = 1, column = 1)

        self.random_button = tk.Button(self.canvas)
        self.random_button.config(text = "Generate Random", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.RandomGeneration())
        self.random_button.grid(row = 2, column = 1)

        self.placeholder1 = tk.Label(self.canvas, width = 2, bg = BGTWO)
        self.placeholder1.grid(row = 1, column = 2)

        self.user_choice = tk.Label(self.canvas)
        self.user_choice.config(text = "Choose Starting Population", bg = BGTWO, fg = FGONE)
        self.user_choice.grid(row = 1, column = 3)

        self.user_choice_button = tk.Button(self.canvas)
        self.user_choice_button.config(text = "Choose Population", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.UserChoice())
        self.user_choice_button.grid(row = 2, column = 3)

        self.placeholder3 = tk.Label(self.canvas, bg = BGTWO)
        self.placeholder3.grid(row = 3, column = 1)
        self.placeholder4 = tk.Label(self.canvas, bg = BGTWO)
        self.placeholder4.grid(row = 0, column = 0)
        self.placeholder5 = tk.Label(self.canvas, bg = BGTWO)
        self.placeholder5.grid(row = 5, column = 4)


        self.backBtn = tk.Button(self.canvas)
        self.backBtn.config(text = "Back", bg = BGONE, fg = FGONE, activebackground = BGTWO, activeforeground = BGONE, command = lambda : self.Back())
        self.backBtn.grid(row = 4, column = 3)
        self.backBtn.bind("<Enter>", self.back_enter)
        self.backBtn.bind("<Leave>", self.back_leave)

    def RandomGeneration(self):
        self.root.destroy()
        rot = tk.Tk()
        RandomGenerationInit(rot, self.loggedInUsn)
        rot.mainloop()

    def UserChoice(self):
        self.root.destroy()
        rot = tk.Tk()
        UserChoiceInit(rot, self.loggedInUsn)
        rot.mainloop()

    def Back(self):
        self.root.destroy()
        rot = tk.Tk()
        user(rot, self.loggedInUsn, True)
        rot.mainloop()

    def back_enter(self, event):
        self.backBtn.config(bg = BGTWO)

    def back_leave(self, event):
        self.backBtn.config(bg = BGONE)

class UserChoiceInit():
    def __init__(self, master, user):
        master.attributes("-topmost", True)
        master.overrideredirect(True)
        init_window(self, master, 150, 75)
        self.loggedInUsn = user

        self.root = master


        s = ttk.Style()
        s.configure("Horizontal.TScale", background = BGTWO)

        self.placeholder1 = tk.Label(self.canvas, width = 2, bg = BGTWO)
        self.placeholder1.grid(row = 0, column = 0)
        self.placeholder2 = tk.Label(self.canvas, width = 2, bg = BGTWO)
        self.placeholder2.grid(row = 0, column = 2)
        self.placeholder3 = tk.Label(self.canvas, bg = BGTWO)
        self.placeholder3.grid(row = 3, column = 0)
        self.placeholder4 = tk.Label(self.canvas, width = 2, bg = BGTWO)
        self.placeholder4.grid(row = 5, column = 0)
        self.placeholder5 = tk.Label(self.canvas, width = 2, bg = BGTWO)
        self.placeholder5.grid(row = 5, column = 5)


        self.wolvesLabel = tk.Label(self.canvas, text = "{Spawn wolves}: 0", bg = BGTWO, fg = FGONE, width = 15)
        self.wolvesLabel.grid(row = 1, column = 1)
        self.deerLabel = tk.Label(self.canvas, text = "{Spawn deer}: 0", bg = BGTWO, fg = FGONE, width = 15)
        self.deerLabel.grid(row = 1, column = 3)


        self.wolvesScale = ttk.Scale(self.canvas, name = "wolvesScale", from_ = 0, to = 50, orient = "horizontal", command = self.WolvesEvent)
        self.wolvesScale.grid(row = 2, column = 1)
        self.deerScale = ttk.Scale(self.canvas, name = "deerScale", from_ = 0, to = 50, orient = "horizontal", command = self.DeerEvent)
        self.deerScale.grid(row = 2, column = 3)

        self.simTimeLbl = tk.Label(self.canvas, bg = BGTWO, fg = FGONE, text = "Enter simulation time in seconds\ngreater than 5 seconds")
        self.simTimeLbl.grid(row = 3, column = 1)
        self.simTimeEntry = tk.Entry(self.canvas)
        self.simTimeEntry.grid(row = 4, column = 1)

        self.indicatorLbl = tk.Label(self.canvas, bg = BGTWO, fg = FGONE, width = 20)
        self.indicatorLbl.grid(row = 4, column = 3)
        
        self.spawnButton = tk.Button(self.canvas)
        self.spawnButton.config(text = "Spawn", command = lambda : self.SpawnAndExit("event"), bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO)
        self.spawnButton.grid(row = 2, column = 4 )
        master.bind("<Return>", self.SpawnAndExit)

        self.backBtn = tk.Button(self.canvas)
        self.backBtn.config(text = "Back", bg = BGONE, fg = FGONE, activebackground = BGTWO, activeforeground = BGONE, command = lambda : self.Back())
        self.backBtn.grid(row = 4, column = 4)
        self.backBtn.bind("<Enter>", self.back_enter)
        self.backBtn.bind("<Leave>", self.back_leave)
        

    def WolvesEvent(self, value):
        roundedValue = round(float(value)) # turn the slider value into a float and round it
        self.wolvesLabel["text"] = "Spawn wolves:", roundedValue # display the rounded value in text
    def DeerEvent(self, value):
        roundedValue = round(float(value))
        self.deerLabel["text"] = "Spawn deer:", roundedValue

    def SpawnAndExit(self, event):
        def isfloat(n):
            try:
                float(n)
                return True
            except ValueError:
                return False

        simLength = self.simTimeEntry.get()
        wolfPopulation = round(self.wolvesScale.get())
        deerPopulation = round(self.deerScale.get())

        if (wolfPopulation == 0 and deerPopulation == 0):
            self.indicatorLbl["text"] = "No starting population"
        else:
            if (isfloat(simLength) or simLength.isnumeric()):
                if (float(simLength) > 5):
                    spawnNumbers = {
                    "wolf": wolfPopulation,
                    "deer": deerPopulation,
                    }
                    
                    for i in spawnNumbers.keys():
                        for j in range(spawnNumbers[i]):
                            sock.send(("inst"+i).encode("UTF-8"))
                            time.sleep(0.1)
                    sock.send(("cmmdsimT" + str(simLength)).encode("UTF-8"))

                    self.root.destroy()
                    rot = tk.Tk()
                    SimulationInProgress(rot, self.loggedInUsn)
                    rot.mainloop()
                else:
                    self.indicatorLbl["text"] = "Invalid Run Time"
            else:
                self.indicatorLbl["text"] = "Invalid Run Time"



    def Back(self):
        self.root.destroy()
        rot = tk.Tk()
        ChooseSimulationType(rot, self.loggedInUsn)
        rot.mainloop()

    def back_enter(self, event):
        self.backBtn.config(bg = BGTWO)

    def back_leave(self, event):
        self.backBtn.config(bg = BGONE)

class RandomGenerationInit():
    def __init__(self, master, user):
        master.attributes("-topmost", True)
        master.overrideredirect(True)
        init_window(self, master, 150, 75)
        self.loggedInUsn = user

        self.root = master

        self.instructionOne = tk.Label(self.canvas, text = "Population Size", bg = BGTWO, fg = FGONE, width = 30)
        self.instructionOne.grid(row = 1, column = 1)
        self.instructionTwo = tk.Label(self.canvas, bg = BGTWO, fg = FGONE)
        self.instructionTwo.grid(row = 3, column = 3)

        self.invalidIndicator = tk.Label(self.canvas, bg = BGTWO, fg = FGONE)
        self.invalidIndicator.grid(row = 5, column = 1)

        self.populationEntry = tk.Entry(self.canvas)
        self.populationEntry.grid(row = 2, column = 1)
        self.populationEntry.focus_set()

        self.generateButton = tk.Button(self.canvas)
        self.generateButton.config(text = "Generate", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = BGTWO, command = lambda : self.StartSimulation("event"))
        self.generateButton.grid(row = 2, column = 3)
        master.bind("<Return>", self.StartSimulation)

        
        self.simTimeLbl = tk.Label(self.canvas, bg = BGTWO, fg = FGONE, text = "Enter simulation time in seconds, greater than 5")
        self.simTimeLbl.grid(row = 3, column = 1)
        self.simTimeEntry = tk.Entry(self.canvas)
        self.simTimeEntry.grid(row = 4, column = 1)


        self.placeholder1 = tk.Label(self.canvas, bg = BGTWO, fg = FGONE, text = "Population: integer less than 101")
        self.placeholder1.grid(row = 0, column = 3)
        self.placeholder2 = tk.Label(self.canvas, width = 1, bg = BGTWO, fg = FGONE)
        self.placeholder2.grid(row = 0, column = 0)
        self.placeholder3 = tk.Label(self.canvas, width = 1, bg = BGTWO, fg = FGONE)
        self.placeholder3.grid(row = 5, column = 4)
        self.placeholder4 = tk.Label(self.canvas, bg = BGTWO, fg = FGONE, text = "Simulation Time: float or integer")
        self.placeholder4.grid(row = 1, column = 3)

        self.backBtn = tk.Button(self.canvas)
        self.backBtn.config(text = "Back", bg = BGONE, fg = FGONE, activebackground = BGTWO, activeforeground = BGONE, command = lambda : self.Back())
        self.backBtn.grid(row = 4, column = 3)
        self.backBtn.bind("<Enter>", self.back_enter)
        self.backBtn.bind("<Leave>", self.back_leave)

        self.populationEntry.lift()
        self.simTimeEntry.lift()
        self.generateButton.lift()
        self.backBtn.lift()


    def StartSimulation(self, event):
        accepted = False
        popSize = self.populationEntry.get()
        validPopSize = False
        try:
            popSize = int(popSize)
        except:
            popSize = None

        def isfloat(n):
            try:
                float(n)
                return True
            except ValueError:
                return False

        simLength = self.simTimeEntry.get()

        if (isfloat(simLength) or simLength.isnumeric()):
            if (float(simLength) > 5):
                if (popSize != None and popSize > 1):
                    accepted = True
                    self.invalidIndicator["text"] = ""
                    if (popSize > 100):
                        popSize = 100
                        self.populationEntry.delete(0, tk.END)
                        self.populationEntry.insert(0, "100") # inserts maximum value of 100 to the entry
                        self.invalidIndicator["text"] = "Population defauled to 100"
                else:
                    self.populationEntry.delete(0, tk.END)
                    self.invalidIndicator["text"] = "Invalid Population Size"

                if (accepted == True):
                    sp = self.InitPopulation(popSize)
                    self.SpawnAndExit(sp)
            else:
                self.invalidIndicator["text"] = "Invalid simulation length"
        else:
            self.invalidIndicator["text"] = "Invalid simulation length"

    def InitPopulation(self, startingPopulation): # function to generate starting population
        preyList = []
        predatorsList = []

        def GenerateStats(): # generate the random stats
            atk = round(random.uniform(5, 8), 2)
            maxHp = round(random.uniform(9, 15), 2)
            speed = round(random.uniform(5, 15), 2)
            viewDistance = round(random.uniform(15, 25), 2)
            isMale = (random.randint(1, 2) % 2)
            guid = str(uuid.uuid4())
            isProgenitor = True

            return atk, maxHp, speed, viewDistance, isMale, guid, isProgenitor

        for i in range(startingPopulation // 2):
            atk, maxHp, speed, viewDistance, isMale, guid, isProgenitor = GenerateStats()
            predatorsList.append(Animal(atk, maxHp, speed, viewDistance, isMale, guid, isProgenitor).__dict__)

        for j in range(startingPopulation // 2):
            atk, maxHp, speed, viewDistance, isMale, guid, isProgenitor = GenerateStats()
            preyList.append(Animal(atk, maxHp, speed, viewDistance, isMale, guid, isProgenitor).__dict__)

        if ((startingPopulation) % 2 != 0): # if desired starting population is an odd number
            if (random.randint(1, 2) % 2): # extra animal will be assigned randomly to predator or prey
                atk, maxHp, speed, viewDistance, isMale, guid, isProgenitor = GenerateStats()
                predatorsList.append(Animal(atk, maxHp, speed, viewDistance, isMale, guid, isProgenitor).__dict__)
            else:
                atk, maxHp, speed, viewDistance, isMale, guid, isProgenitor = GenerateStats()
                preyList.append(Animal(atk, maxHp, speed, viewDistance, isMale, guid, isProgenitor).__dict__)

        # return predatorsList, preyList # for JSON file
        return ("jsonpred" + json.dumps(predatorsList)), ("jsonprey" + json.dumps(preyList)) # for JSON string


    def SpawnAndExit(self, startingPopulation):
        sentPredatorInfo = False
        sentPreyInfo = False

        sock.send(("cmmdsimT" + str(self.simTimeEntry.get())).encode("UTF-8"))

        while (sentPredatorInfo != True):
            time.sleep(1)
            sock.sendall(startingPopulation[0].encode("UTF-8")) # startingPopulation[0] is the predators list
        
            receivedData = sock.recv(1024).decode("UTF-8")
            if (receivedData == "receivedStartingPopulation"):
                sentPredatorInfo = True

        while (sentPreyInfo != True):
            time.sleep(1)
            sock.sendall(startingPopulation[1].encode("UTF-8")) # startingPopulation[1] is the prey list
        
            receivedData = sock.recv(1024).decode("UTF-8")
            if (receivedData == "receivedStartingPopulation"):
                sentPreyInfo = True

        self.root.destroy()
        rot = tk.Tk()
        SimulationInProgress(rot, self.loggedInUsn)
        rot.mainloop()
    
    def Back(self):
        self.root.destroy()
        rot = tk.Tk()
        ChooseSimulationType(rot, self.loggedInUsn)
        rot.mainloop()

    def back_enter(self, event):
        self.backBtn.config(bg = BGTWO)

    def back_leave(self, event):
        self.backBtn.config(bg = BGONE)

class SimulationInProgress():
    def __init__(self, master, user):
        master.attributes("-topmost", True)
        master.overrideredirect(True)
        init_window(self, master, 150, 75)
        self.loggedInUsn = user

        self.root = master

        self.harvestDataBtn = tk.Button(self.canvas)
        self.harvestDataBtn.config(text = "Harvest Data", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.HarvestData())
        self.harvestDataBtn.grid(row = 1, column = 1)

        self.placeholder1 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder1.grid(row = 0, column = 0)
        self.placeholder2 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder2.grid(row = 3, column = 3)

    def HarvestData(self):
        attempts = 0
        receivedData = sock.recv(1024).decode("UTF-8")
        while (receivedData[0:7] != "simover" and attempts <= 5):
            receivedData = sock.recv(1024).decode("UTF-8")
            attempts += 1
            time.sleep(0.1)

        sock.send("resultsReceived".encode("UTF-8"))

        firstInstance = receivedData.index("simover") # find index of "simover" string on 7th index and after
        endOfData = receivedData.index("simover", firstInstance + 7)

        data = receivedData[firstInstance + 7:endOfData]
        populationResultsJson = data[0:data.index("animalData")]
        animalStatsJson = data[data.index("animalData")+10:]
        animalStatsJson = json.loads(animalStatsJson)

        AddResults(self.loggedInUsn, animalStatsJson, populationResultsJson, databasePath, databaseCommandsSQL)

        self.root.destroy()
        rot = tk.Tk()
        user(rot, self.loggedInUsn, True)
        rot.mainloop()

class ReviewResults():
    def __init__(self, master, user):
        master.attributes("-topmost", True)
        master.overrideredirect(True)
        init_window(self, master, 150, 75)
        self.loggedInUsn = user

        self.root = master

        self.userData = QueryData(self.loggedInUsn, databasePath, databaseCommandsSQL)

        if (not self.userData): # empty list equals false so if the list is empty, the user will be returned to the previous window
            self.Back(False)
        else:
            self.simulationDates = [i[3] for i in self.userData]
            self.simulationDates.reverse()

            self.string_var = tk.StringVar(self.canvas)
            self.string_var.set("select result")
            self.results_menu = tk.OptionMenu(self.canvas, self.string_var, *self.simulationDates)
            self.results_menu.config(width = 20, bd = 0, bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO)
            self.results_menu["menu"].config(bd = 0, bg = BGTWO, fg = FGTWO, activebackground = BGONE, activeforeground = FGTWO, selectcolor = BGTHREE)
            self.results_menu.grid(row = 1, column = 1)

            self.flip_list_button = tk.Button(self.canvas)
            self.flip_list_button.config(width = 15, text = "Sort by Oldest", bg = BGTWO,fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = self.FlipList)
            self.flip_list_button.grid(row = 1, column = 2)

            self.view_results_button = tk.Button(self.canvas)
            self.view_results_button.config(text = "View Results", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.ViewResults(self.string_var.get()))
            self.view_results_button.grid(row = 3, column = 1)

            self.backBtn = tk.Button(self.canvas)
            self.backBtn.config(text = "Back", bg = BGONE, fg = FGONE, activebackground = BGTWO, activeforeground = BGONE, command = lambda : self.Back(True))
            self.backBtn.grid(row = 4, column = 3)
            self.backBtn.bind("<Enter>", self.back_enter)
            self.backBtn.bind("<Leave>", self.back_leave)

            self.instruction_label = tk.Label(self.canvas, text = "Select Simulation Result To View", bg = BGTWO, fg = FGONE)
            self.instruction_label.grid(row = 0, column = 1)

            self.copyResults = tk.Button(self.canvas)
            self.copyResults.config(text = "Copy This Record", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.CopyResult(self.string_var.get()))
            self.copyResults.grid(row = 4, column = 2)

            self.downloadResults = tk.Button(self.canvas)
            self.downloadResults.config(text = "Download All Results", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.DownloadResults(self.string_var.get()))
            self.downloadResults.grid(row = 3, column = 2)

            self.placeholder1 = tk.Label(self.canvas, bg = BGTWO, width = 2)
            self.placeholder1.grid(row = 0, column = 0)
            self.placeholder2 = tk.Label(self.canvas, bg = BGTWO)
            self.placeholder2.grid(row = 2, column = 2)
            self.placeholder3 = tk.Label(self.canvas, bg = BGTWO, width = 2)
            self.placeholder3.grid(row = 4, column = 4)
            self.placeholder3 = tk.Label(self.canvas, bg = BGTWO, width = 2)
            self.placeholder3.grid(row = 5, column = 0)

            self.indicatorLbl = tk.Label(self.canvas, bg = BGTWO, fg = FGONE)
            self.indicatorLbl.grid(row = 4, column = 1)


    def FlipList(self):
        self.simulationDates.reverse() # reverse the list of date and times

        if (self.flip_list_button["text"] == "Sort by Oldest"):
            self.flip_list_button.config(text = "Sort by Newest")
        else:
            self.flip_list_button.config(text = "Sort by Oldest")

        options = self.simulationDates # temporary variable options stores this reverse

        self.results_menu["menu"].delete(0, tk.END) # delete the existing menu

        for i in options: # loop through the reversed list, adding the options back in with label text and the on click command to change the value of string_var to the text
            self.results_menu["menu"].add_command(label = i, command = tk._setit(self.string_var, i))
        self.string_var.set("select result") # select the default result

    def ViewResults(self, record):
        if (record != "select result"):
            self.root.destroy()
            rot = tk.Tk()
            DisplayData(rot, self.loggedInUsn, self.userData, record)
            rot.mainloop()
        else:
            self.indicatorLbl["text"] = "Select a record of data"

    def CopyResult(self, dateRecord):
        if (dateRecord != "select result"):
            data = QueryData(self.loggedInUsn, databasePath, databaseCommandsSQL)
            for i in data:
                if (i[3] == dateRecord):
                    copyData = str(i)
            clipboard.copy(copyData)
        else:
            self.indicatorLbl["text"] = "Select a record of data"

    def DownloadResults(self, dateRecord):
        downloadData = str(QueryData(self.loggedInUsn, databasePath, databaseCommandsSQL))
        
        directory = "UserData"
        currentDirectory = os.getcwd()
        targetDirectoryPath = os.path.join(currentDirectory, directory)
        
        if (os.path.isdir(targetDirectoryPath)):
            print("folder exists")
        else:
            print("folder created")
            os.mkdir(targetDirectoryPath)

        userFile = self.loggedInUsn + "_Data.txt"
        targetFilePath = os.path.join(targetDirectoryPath, userFile)
        f = open(targetFilePath, "w")
        f.write(downloadData)
        f.close()
            

    def Back(self, hasResults):
        self.root.destroy()
        rot = tk.Tk()
        user(rot, self.loggedInUsn, hasResults)
        rot.mainloop()

    def back_enter(self, event):
        self.backBtn.config(bg = BGTWO)

    def back_leave(self, event):
        self.backBtn.config(bg = BGONE)

class DisplayData():
    def __init__(self, master, user, userData, dateRecord):
        master.attributes("-topmost", True)
        master.overrideredirect(True)
        init_window(self, master, 1000, 75)
        self.loggedInUsn = user
        self.root = master
        self.userData = userData
        self.dateRecord = dateRecord

        for i in userData:
            if (i[3] == self.dateRecord):
                self.run_id = i[0]


        self.cmdDict = getCommands(databaseCommandsSQL)
        con, cur = establishConnection(databasePath)

        self.query = self.cmdDict["populationValues"]
        cur.execute(self.query.format(runId = self.run_id))
        self.populationValues = cur.fetchone()[0] # to get the array and not the tuple holding it
        self.populationValues = json.loads(self.populationValues)

        self.query = self.cmdDict["wolfAttributes"]
        cur.execute(self.query.format(runId = self.run_id))
        self.wolfStats = cur.fetchone()

        self.query = self.cmdDict["deerAttributes"]
        cur.execute(self.query.format(runId = self.run_id))
        self.deerStats = cur.fetchone()
        
        con.commit()
        con.close()

        self.timeValues = [i[0] for i in self.populationValues]
        self.wolfPopulationValues = [i[1] for i in self.populationValues]
        self.deerPopulationValues = [i[2] for i in self.populationValues]


        self.wolfPopLbl = tk.Label(self.canvas, text = "Show wolf population graph", bg = BGTWO, fg = FGONE)
        self.wolfPopLbl.grid(row = 1, column = 1)
        self.wolfPopBtn = tk.Button(self.canvas)
        self.wolfPopBtn.config(text = "Show Graph", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.WolfPopulation(self.run_id, self.dateRecord, self.timeValues, self.wolfPopulationValues))
        self.wolfPopBtn.grid(row = 1, column = 3)

        self.deerPopLbl = tk.Label(self.canvas, text = "Show deer population graph", bg = BGTWO, fg = FGONE)
        self.deerPopLbl.grid(row = 3, column = 1)
        self.deerPopBtn = tk.Button(self.canvas)
        self.deerPopBtn.config(text = "Show Graph", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.DeerPopulation(self.run_id, self.dateRecord, self.timeValues, self.deerPopulationValues))
        self.deerPopBtn.grid(row = 3, column = 3)

        self.WaDPopLbl = tk.Label(self.canvas, text = "Show wolf and deer populations graph", bg = BGTWO, fg = FGONE)
        self.WaDPopLbl.grid(row = 5, column = 1)
        self.WaDPopBtn = tk.Button(self.canvas)
        self.WaDPopBtn.config(text = "Show Graph", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.WaDPopulation(self.run_id, self.dateRecord, self.timeValues, self.wolfPopulationValues, self.deerPopulationValues))
        self.WaDPopBtn.grid(row = 5, column = 3)

        self.wolfStatsLbl = tk.Label(self.canvas, text = "Show wolf attributes", bg = BGTWO, fg = FGONE)
        self.wolfStatsLbl.grid(row = 7, column = 1)
        self.wolfStatsBtn = tk.Button(self.canvas)
        self.wolfStatsBtn.config(text = "Show Graph", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.WolfStatsGraph(self.run_id, self.dateRecord, self.wolfStats))
        self.wolfStatsBtn.grid(row = 7, column = 3)

        self.deerStatsLbl = tk.Label(self.canvas, text = "Show deer attributes", bg = BGTWO, fg = FGONE)
        self.deerStatsLbl.grid(row = 9, column = 1)
        self.deerStatsBtn = tk.Button(self.canvas)
        self.deerStatsBtn.config(text = "Show Graph", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.DeerStatsGraph(self.run_id, self.dateRecord, self.deerStats))
        self.deerStatsBtn.grid(row = 9, column = 3)

        self.WaDStatsLbl = tk.Label(self.canvas, text = "Show wolf and deer attributes", bg = BGTWO, fg = FGONE)
        self.WaDStatsLbl.grid(row = 11, column = 1)
        self.WaDStatsBtn = tk.Button(self.canvas)
        self.WaDStatsBtn.config(text = "Show Graph", bg = BGTWO, fg = FGONE, activebackground = BGONE, activeforeground = FGTWO, command = lambda : self.WaDStatsGraph(self.run_id, self.dateRecord, self.wolfStats, self.deerStats))
        self.WaDStatsBtn.grid(row = 11, column = 3)

        
        self.backBtn = tk.Button(self.canvas)
        self.backBtn.config(text = "Back", bg = BGONE, fg = FGONE, activebackground = BGTWO, activeforeground = BGONE, command = lambda : self.Back())
        self.backBtn.grid(row = 13, column = 5)
        self.backBtn.bind("<Enter>", self.back_enter)
        self.backBtn.bind("<Leave>", self.back_leave)

        
        self.placeholder1 = tk.Label(self.canvas, bg = BGTWO, fg = BGONE, text = "Graph Options")
        self.placeholder1.grid(row = 0, column = 1)
        self.placeholder2 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder2.grid(row = 2, column = 0)
        self.placeholder3 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder3.grid(row = 4, column = 0)
        self.placeholder4 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder4.grid(row = 6, column = 0)
        self.placeholder5 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder5.grid(row = 8, column = 0)
        self.placeholder6 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder6.grid(row = 10, column = 0)
        self.placeholder7 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder7.grid(row = 12, column = 0)
        self.placeholder8 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder8.grid(row = 14, column = 0)
        self.placeholder9 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder9.grid(row = 0, column = 2)
        self.placeholder10 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder10.grid(row = 0, column = 4)
        self.placeholder11 = tk.Label(self.canvas, bg = BGTWO, width = 2)
        self.placeholder11.grid(row = 0, column = 6)



    def WolfPopulation(self, run_id, dateRecord, timeValues, wolfPopulationValues):
        fig, ax = plt.subplots()
        ax.plot(timeValues, wolfPopulationValues, label = "Wolves", color = myOrange)
        plt.title("Wolf Population x Time", fontsize = 8)
        plt.title("Run ID: " + str(run_id), loc = "left", fontsize = 8)
        plt.title(dateRecord, loc = "right", fontsize = 8)
        plt.xlabel("time/s")
        plt.ylabel("Population Number")
        ax.legend(loc = "upper right", framealpha = 0.5)
        plt.show()

    def DeerPopulation(self, run_id, dateRecord, timeValues, deerPopulationValues):
        fig, ax = plt.subplots()
        ax.plot(timeValues, deerPopulationValues, label = "Deer", color = myBlue)
        plt.title("Deer Population x Time", fontsize = 8)
        plt.title("Run ID: " + str(run_id), loc = "left", fontsize = 8)
        plt.title(dateRecord, loc = "right", fontsize = 8)
        plt.xlabel("time/s")
        plt.ylabel("Population Number")
        ax.legend(loc = "upper right", framealpha = 0.5)
        plt.show()

    def WaDPopulation(self, run_id, dateRecord, timeValues, wolfPopulationValues, deerPopulationValues):
        fig, ax = plt.subplots()
        ax.plot(timeValues, wolfPopulationValues, label = "Wolves", color = myOrange)
        ax.plot(timeValues, deerPopulationValues, label = "Deer", color = myBlue)
        plt.title("Wolf and Deer Populations x Time", fontsize = 8)
        plt.title("Run ID: " + str(run_id), loc = "left", fontsize = 8)
        plt.title(dateRecord, loc = "right", fontsize = 8)
        plt.xlabel("time/s")
        plt.ylabel("Population Number")
        ax.legend(loc = "upper right", framealpha = 0.5)
        plt.show()
        
    def WolfStatsGraph(self, run_id, dateRecord, wolfStats):
        categories = ["Attack", "Max Health", "Speed", "View Distance"]
        categories.append(categories[0])

        wolfStats = [i for i in wolfStats] # turn wolfStats into a list of itself because tuples are immutable
        wolfStats.append(wolfStats[0]) # and wolfStats needs to be altered
        
        label_placement = np.linspace(start = 0, stop = 2 * np.pi, num = len(wolfStats))
        plt.figure(figsize = (6, 6))
        plt.subplot(polar = True)
        plt.plot(label_placement, wolfStats, color = myOrange, label = "Wolves")
        lines, labels = plt.thetagrids(np.degrees(label_placement), labels = categories)
        plt.title("Average Wolf Attributes", fontsize = 8)
        plt.title("Run ID: " + str(run_id), loc = "left", fontsize = 8)
        plt.title(dateRecord, loc = "right", fontsize = 8)
        plt.legend(loc = "upper right", framealpha = 0.5)
        plt.show()

    def DeerStatsGraph(self, run_id, dateRecord, deerStats):
        categories = ["Attack", "Max Health", "Speed", "View Distance"]
        categories.append(categories[0])

        deerStats = [i for i in deerStats] # turn wolfStats into a list of itself because tuples are immutable
        deerStats.append(deerStats[0]) # and wolfStats needs to be altered
        
        label_placement = np.linspace(start = 0, stop = 2 * np.pi, num = len(deerStats))
        plt.figure(figsize = (6, 6))
        plt.subplot(polar = True)
        plt.plot(label_placement, deerStats, color = myBlue, label = "Deer")
        lines, labels = plt.thetagrids(np.degrees(label_placement), labels = categories)
        plt.title("Average Deer Attributes", fontsize = 8)
        plt.title("Run ID: " + str(run_id), loc = "left", fontsize = 8)
        plt.title(dateRecord, loc = "right", fontsize = 8)
        plt.legend(loc = "upper right", framealpha = 0.5)
        plt.show()

    def WaDStatsGraph(self, run_id, dateRecord, wolfStats, deerStats):
        categories = ["Attack", "Max Health", "Speed", "View Distance"]
        categories.append(categories[0])
        #
        wolfStats = [i for i in wolfStats] # turn wolfStats into a list of itself because tuples are immutable
        wolfStats.append(wolfStats[0]) # and wolfStats needs to be altered
        deerStats = [i for i in deerStats]
        deerStats.append(deerStats[0])
        
        label_placement = np.linspace(start = 0, stop = 2 * np.pi, num = len(deerStats))
        plt.figure(figsize = (6, 6))
        plt.subplot(polar = True)
        plt.plot(label_placement, wolfStats, color = myOrange, label = "Wolves")
        plt.plot(label_placement, deerStats, color = myBlue, label = "Deer")
        lines, labels = plt.thetagrids(np.degrees(label_placement), labels = categories)
        plt.title("Average Deer Attributes", fontsize = 8)
        plt.title("Run ID: " + str(run_id), loc = "left", fontsize = 8)
        plt.title(dateRecord, loc = "right", fontsize = 8)
        plt.legend(loc = "upper right", framealpha = 0.5)
        plt.show()

    def Back(self):
        self.root.destroy()
        rot = tk.Tk()
        ReviewResults(rot, self.loggedInUsn)
        rot.mainloop()

    def back_enter(self, event):
        self.backBtn.config(bg = BGTWO)

    def back_leave(self, event):
        self.backBtn.config(bg = BGONE)



root = tk.Tk()
normal_font = tkfont.Font(family = "Verdana", size = 10)
bold_font = tkfont.Font(family = "Verdana", size = 9, weight = "bold")

def connectDB():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(BASE_DIR, databasePath)

    con = sqlite3.connect(db_path)
    cur = con.cursor()
    
    return con, cur

def init_window(self, master, start_x, start_y):
    def mapped(event):
        self.root.update_idletasks()
        self.root.overrideredirect(True)
        self.root.state("normal")

    def window_pos(event):
        # offset_x = self.root.winfo_pointerx()
        # offset_y = self.root.winfo_pointery()
        # print(offset_x, offset_y)
        self._offsetx = self.root.winfo_pointerx() - self.root.winfo_rootx()
        self._offsety = self.root.winfo_pointery() - self.root.winfo_rooty()

    def move_window(event):
        # offset_x = self.root.winfo_pointerx()
        # offset_y = self.root.winfo_pointery()
        # delta_x = self.root.winfo_pointerx() - offset_x
        # delta_y = self.root.winfo_pointery() - offset_y

        # x_pos = self._init_x + delta_x
        # y_pos = self._init_y + delta_y
        # self.root.geometry("+{x}+{y}".format(x = x_pos, y = y_pos))
        # self._init_x = x_pos
        # self._init_y = y_pos
        x = self.root.winfo_pointerx() - self._offsetx
        y = self.root.winfo_pointery() - self._offsety
        self.root.geometry(f"+{x}+{y}")

    def resize(event):
        self.root.geometry("{width}x{height}".format(width = event.width, height = event.height))


    _init_x = start_x
    _init_y = start_y
    master.geometry("+{x}+{y}".format(x = _init_x, y = _init_y))

    self.title_bar = tk.Frame(master)
    self.title_bar.pack(expand = 1, side = tk.TOP, fill = tk.X)
    self.title_bar.config(bg = BGONE)
    self.title_bar.bind("<Button-1>", window_pos)
    self.title_bar.bind("<B1-Motion>", move_window)


    self.canvas = tk.Frame(master)
    self.canvas.pack(expand = 1, side = tk.BOTTOM, fill = tk.BOTH)
    self.canvas.config(bg = BGTWO, width = 600, height = 300)
    self.canvas.bind("<Map>", mapped)


    x_button(self)
    fullscreen(self)
    minimise(self)

def x_button(self):
    def close_window(self):
        self.root.destroy()
        sys.exit(0)

    def x_enter(event):
        self.x_button.config(bg = BGTWO)
    def x_leave(event):
        self.x_button.config(bg = BGONE, fg = FGONE)

    normal_font = tkfont.Font(family = "Verdana", size = 10)
    bold_font = tkfont.Font(family = "Verdana", size = 9, weight = "bold")
    self.x_button = tk.Button(self.title_bar)
    self.x_button.pack(side = tk.RIGHT)
    self.x_button.config(font = bold_font, text = "X", command = lambda : close_window(self), relief = tk.GROOVE, bg  = BGONE, fg = FGONE, activebackground = BGTHREE, activeforeground = BGONE)
    self.x_button.bind("<Enter>", x_enter)
    self.x_button.bind("<Leave>", x_leave)

def fullscreen(self):
    def set_fullscreen(self):
        global is_maximised
        if is_maximised == False:
            self.root.state("zoomed")
            is_maximised = True
        else:
            self.root.state("normal")
            is_maximised = False

    def full_enter(event):
        self.fullscreen.config(bg = BGTWO)
    def full_leave(event):
        self.fullscreen.config(bg = BGONE, fg = FGONE)

    normal_font = tkfont.Font(family = "Verdana", size = 10)
    bold_font = tkfont.Font(family = "Verdana", size = 9, weight = "bold")
    self.fullscreen = tk.Button(self.title_bar)
    self.fullscreen.pack(side = tk.RIGHT)
    self.fullscreen.config(font = bold_font, text = "☐", command = lambda : set_fullscreen(self), relief = tk.GROOVE, bg = BGONE, fg = FGONE, activebackground = BGTHREE, activeforeground = BGONE)
    self.fullscreen.bind("<Enter>", full_enter)
    self.fullscreen.bind("<Leave>", full_leave)

def minimise(self):
    def minimise_function(self):
        self.root.update_idletasks()
        self.root.overrideredirect(False)
        self.root.state("iconic")

    def mini_enter(event):
        self.minimise.config(bg = BGTWO)
    def mini_leave(event):
        self.minimise.config(bg = BGONE, fg = FGONE)

    normal_font = tkfont.Font(family = "Verdana", size = 10)
    bold_font = tkfont.Font(family = "Verdana", size = 9, weight = "bold")
    self.minimise = tk.Button(self.title_bar)
    self.minimise.pack(side = tk.RIGHT)
    self.minimise.config(font = bold_font, text = "—", command = lambda : minimise_function(self), relief = tk.GROOVE, bg = BGONE, fg = FGONE, activebackground = BGTHREE, activeforeground = BGONE)
    self.minimise.bind("<Enter>", mini_enter)
    self.minimise.bind("<Leave>", mini_leave)



# call new_user class manually to create first user
log_in(root)
# admin(root, "admin1")
# new_user(root, "admin1")
# edit_users(root, "admin1")
# user(root, "user1", True)
# UserChoiceInit(root, "user1")
# ReviewResults(root, "user6")
# SimulationInProgress(root, "user1")

root.mainloop()