INSERT INTO results (RUNNER_ID, POPULATION_VALUES, DATE_TIME) VALUES (
    (SELECT USER_ID FROM login WHERE USERNAME = "{usn}"),
    "{populationValues}",
    "{dateAndTime}"
);
INSERT INTO wolf_results (RUN_ID, POPULATION, AVG_ATTACK, AVG_MAX_HEALTH, AVG_SPEED, AVG_VIEW_DISTANCE) VALUES (
    (SELECT RUN_ID FROM results WHERE RUN_ID = {run_id}),
    {population},
    {attack},
    {maxHealth},
    {speed},
    {viewDistance}
);
INSERT INTO deer_results (RUN_ID, POPULATION, AVG_ATTACK, AVG_MAX_HEALTH, AVG_SPEED, AVG_VIEW_DISTANCE) VALUES (
    (SELECT RUN_ID FROM results WHERE RUN_ID = {run_id}),
    {population},
    {attack},
    {maxHealth},
    {speed},
    {viewDistance}
);
SELECT USER_ID FROM login WHERE USERNAME = "{simulationRunnerUsn}";
SELECT * FROM results WHERE RUNNER_ID = "{simulationRunnerId}";
SELECT POPULATION_VALUES FROM results WHERE RUN_ID = "{runId}";
SELECT AVG_ATTACK, AVG_MAX_HEALTH, AVG_SPEED, AVG_VIEW_DISTANCE FROM wolf_results WHERE RUN_ID = "{runId}";
SELECT AVG_ATTACK, AVG_MAX_HEALTH, AVG_SPEED, AVG_VIEW_DISTANCE FROM deer_results WHERE RUN_ID = "{runId}";