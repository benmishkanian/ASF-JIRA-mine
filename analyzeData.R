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
    summaryCols <- c("issuesReported", "issuesResolved")
    volunteers <- contributors[contributors$isVolunteer==1, summaryCols]
    employees <- contributors[contributors$isVolunteer==0, summaryCols]
    print("summary for volunteers:")
    print(summary(volunteers))
    print(paste("sd: ", sd(volunteers[,"issuesReported"]), "sd: ", sd(volunteers[,"issuesResolved"])))
    topTableCols <- c("email", "issuesReported", "issuesResolved")
    print("Top 10 reporters:")
    print(contributors[contributors$isVolunteer==1, topTableCols][order(volunteers$issuesReported, decreasing = TRUE)[1:10],])
    print("Top 10 resolvers:")
    print(contributors[contributors$isVolunteer==1, topTableCols][order(volunteers$issuesResolved, decreasing = TRUE)[1:10],])
    print(paste(replicate(80,"-"), collapse=""))
    print("summary for employees:")
    print(summary(employees))
    print(paste("sd: ", sd(employees[,"issuesReported"]), "sd: ", sd(volunteers[,"issuesResolved"])))
    
    invisible(dbDisconnect(dbConnection))
}

analyzeData()