# This is database_rw2.ipynb in .py form for easy import to the login script

import sqlite3
import random
from datetime import datetime

def getCommands(databaseCommandsSQL): 
    fd = open(databaseCommandsSQL, "r")

    sqlFile = fd.read()
    fd.close()

    sqlCommands = sqlFile.split(";")

    cmdDict = {"results": None, "wolf": None, "deer": None, "queryRunnerId": None, "queryRunnerData": None, "populationValues": None, "wolfAttributes": None, "deerAttributes": None}
    i = 0
    for key in cmdDict:
        cmdDict[key] = sqlCommands[i]
        i += 1

    return cmdDict

def generateData():
    randNums = []
    for i in range(10):
        if i % 5 == 0: # generates an integer for population as there are 5 generated pieces of data per row
            randNums.append(random.randint(0, 10))
        else:
            randNums.append(round(random.uniform(0, 5), 3))
    
    return randNums

def establishConnection(databasePath):
    con = sqlite3.connect(databasePath)
    cur = con.cursor()

    return con, cur

def AddResults(username, data, populationResults, databasePath, databaseCommandsSQL):
    cmdDict = getCommands(databaseCommandsSQL)

    wolfData = data[0:5]
    deerData = data[5:10]

    con, cur = establishConnection(databasePath)

    now = datetime.now().strftime("%d/%m/%Y - %H:%M:%S")
    cur.execute(cmdDict["results"].format(usn = username, populationValues = populationResults, dateAndTime = now))


    query = "SELECT MAX(RUN_ID) FROM results WHERE RUNNER_ID = ((SELECT USER_ID FROM login WHERE USERNAME = '{username}'))"
    cur.execute(query.format(username = username))
    runId = cur.fetchone()

    cur.execute(cmdDict["wolf"].format(run_id = runId[0], population = wolfData[0], attack = wolfData[1], maxHealth = wolfData[2], speed = wolfData[3], viewDistance = wolfData[4]))
    cur.execute(cmdDict["deer"].format(run_id = runId[0], population = deerData[0], attack = deerData[1], maxHealth = deerData[2], speed = deerData[3], viewDistance = deerData[4]))

    con.commit()
    con.close()

def QueryData(usn, databasePath, databaseCommandsSQL):
    cmdDict = getCommands(databaseCommandsSQL)

    con, cur = establishConnection(databasePath)
    query = cmdDict["queryRunnerId"]
    cur.execute(query.format(simulationRunnerUsn = usn))
    runnerId = cur.fetchone()[0]

    query = cmdDict["queryRunnerData"]
    cur.execute(query.format(simulationRunnerId = runnerId))
    data = cur.fetchall()
    con.commit()
    con.close()

    return data