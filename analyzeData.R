library(RSQLite)
dbConnection <- dbConnect(SQLite(), "sqlite.db")

queryDatabase <- function(query) {
    dbGetQuery(dbConnection, query)
}

getSummary <- function(isVolunteer) {
    isVolunteer <- as.numeric(isVolunteer)
    stopifnot(isVolunteer == 0 || isVolunteer == 1)
    summary(queryDatabase(paste("select * from contributors where isVolunteer=",isVolunteer))[,c("issuesReported", "issuesResolved")])
}