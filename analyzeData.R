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
    
    reportedByVolunteer <- dbGetQuery(dbConnection, "select contributors.isVolunteer as reportedByVolunteer from issues inner join contributors on issues.reporter_id=contributors.id")
    contributors <- dbGetQuery(dbConnection, "select * from contributors")
    summaryCols <- c("issuesReported", "issuesResolved")
    topTableCols <- c("email", "issuesReported", "issuesResolved")
    
    showDataFor <- function(contributorClass) {
        print(paste(replicate(80,"-"), collapse=""))
        contributorClassName <- if (contributorClass == 0) "employees" else "volunteers"
        print(paste("Data for ", contributorClassName, ":"))
        classReportCount <- length(reportedByVolunteer[reportedByVolunteer == contributorClass])
        print(paste(contributorClassName, " reported ", classReportCount, " issues"))
        contributorsOfClass <- contributors[contributors$isVolunteer==contributorClass, summaryCols]
        print(paste("summary for ", contributorClassName, ":"))
        print(summary(contributorsOfClass))
        print(paste("sd: ", sd(contributorsOfClass[,"issuesReported"]), "sd: ", sd(contributorsOfClass[,"issuesResolved"])))
        print("Top 10 reporters:")
        print(contributors[contributors$isVolunteer==contributorClass, topTableCols][order(contributorsOfClass$issuesReported, decreasing = TRUE)[1:10],])
        print("Top 10 resolvers:")
        print(contributors[contributors$isVolunteer==contributorClass, topTableCols][order(contributorsOfClass$issuesResolved, decreasing = TRUE)[1:10],])
    }
    
    lapply(c(0,1), showDataFor)
    
    invisible(dbDisconnect(dbConnection))
}

analyzeData()