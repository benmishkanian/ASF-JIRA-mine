library(RSQLite)

queryDatabase <- function(query) {
    dbGetQuery(dbConnection, query)
}

getContributors <- function() {
    queryDatabase("select * from contributors")
}

getSummary <- function(isVolunteer) {
    isVolunteer <- as.numeric(isVolunteer)
    stopifnot(isVolunteer == 0 || isVolunteer == 1)
    print(summary(queryDatabase(paste("select * from contributors where isVolunteer=",isVolunteer))[,c("issuesReported", "issuesResolved")]))
}

analyzeData <- function() {
    dbConnection <- dbConnect(SQLite(), "sqlite.db")
    
    contributors <- dbGetQuery(dbConnection, "select * from contributors")
    cols <- c("issuesReported", "issuesResolved")
    print("summary for volunteers")
    print(summary(contributors[contributors$isVolunteer==1, cols]))
    print("summary for employees")
    print(summary(contributors[contributors$isVolunteer==0, cols]))
    
    invisible(dbDisconnect(dbConnection))
}