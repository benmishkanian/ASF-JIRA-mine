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

printDivider <- function() {
    print(paste(replicate(80,"-"), collapse=""))
}


analyzeData <- function() {
    dbConnection <- dbConnect(SQLite(), "sqlite.db")
    
    reportedByVolunteer <- dbGetQuery(dbConnection, "select contributors.isVolunteer as reportedByVolunteer from issues inner join contributors on issues.reporter_id=contributors.id")
    resolvedByVolunteer <- dbGetQuery(dbConnection, "select contributors.isVolunteer as resolvedByVolunteer from issues inner join contributors on issues.resolver_id=contributors.id")

    contributors <- dbGetQuery(dbConnection, "select * from contributors")
    summaryCols <- c("issuesReported", "issuesResolved")
    topTableCols <- c("email", "issuesReported", "issuesResolved")
    contributorTypes <- c("employees", "volunteers")
    
    showDataFor <- function(contributorClass) {
        printDivider()
        contributorClassName <- contributorTypes[contributorClass]
        print(paste("Data for ", contributorClassName, ":", sep = ""))
        classReportCount <- length(reportedByVolunteer[reportedByVolunteer == contributorClass])
        classResolveCount <- length(resolvedByVolunteer[resolvedByVolunteer == contributorClass])
        print(paste(contributorClassName, "reported", classReportCount, "issues"))
        print(paste(contributorClassName, "resolved", classResolveCount, "issues"))
        contributorsOfClass <- contributors[contributors$isVolunteer==contributorClass, summaryCols]
        print(paste("summary for ", contributorClassName, ":", sep = ""))
        print(summary(contributorsOfClass))
        print(paste("sd:", sd(contributorsOfClass[,"issuesReported"]), "sd:", sd(contributorsOfClass[,"issuesResolved"])))
        print("Top 10 reporters:")
        print(contributors[contributors$isVolunteer==contributorClass, topTableCols][order(contributorsOfClass$issuesReported, decreasing = TRUE)[1:10],])
        print("Top 10 resolvers:")
        print(contributors[contributors$isVolunteer==contributorClass, topTableCols][order(contributorsOfClass$issuesResolved, decreasing = TRUE)[1:10],])
    }
    
    lapply(c(0,1), showDataFor)
    
    printDivider()
    print("Current count of issues at each priority level, grouped by reporter class:")
    priorityLevels <- c("Blocker", "Critical", "Major", "Minor", "Trivial")
    priorityReportedByVolunteerTable <- dbGetQuery(dbConnection, "select issues.currentPriority, contributors.isVolunteer as reportedByVolunteer from issues inner join contributors on issues.reporter_id=contributors.id")
    getIssueCountByReporters <- function(priority, reportedByVolunteer) {
        nrow(priorityReportedByVolunteerTable[priorityReportedByVolunteerTable$currentPriority == priority & priorityReportedByVolunteerTable$reportedByVolunteer == reportedByVolunteer,])
    }
    priorityTable <- outer(priorityLevels, c(0,1), Vectorize(getIssueCountByReporters))
    rownames(priorityTable) <- priorityLevels
    colnames(priorityTable) <- contributorTypes
    print(priorityTable)
    
    printDivider()
    print("Current count of resolved issues at each priority level, grouped by resolver class:")
    priorityResolvedByVolunteerTable <- dbGetQuery(dbConnection, "select issues.currentPriority, contributors.isVolunteer as resolvedByVolunteer from issues inner join contributors on issues.resolver_id=contributors.id")
    getIssueCountByResolvers <- function(priority, resolvedByVolunteer) {
        nrow(priorityResolvedByVolunteerTable[priorityResolvedByVolunteerTable$currentPriority == priority & priorityResolvedByVolunteerTable$resolvedByVolunteer == resolvedByVolunteer,])
    }
    priorityTable <- outer(priorityLevels, c(0,1), Vectorize(getIssueCountByResolvers))
    rownames(priorityTable) <- priorityLevels
    colnames(priorityTable) <- contributorTypes
    print(priorityTable)
    
    invisible(dbDisconnect(dbConnection))
}

analyzeData()