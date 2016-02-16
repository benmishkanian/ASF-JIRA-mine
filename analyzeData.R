library(RSQLite)
library(e1071)

queryDatabase <- function(query) {
    dbGetQuery(dbConnection, query)
}

getContributors <- function() {
    queryDatabase("select * from contributors")
}

getSummary <- function(hasFreeEmail) {
    hasFreeEmail <- as.numeric(hasFreeEmail)
    stopifnot(hasFreeEmail == 0 || hasFreeEmail == 1)
    print(summary(queryDatabase(paste("select * from contributors where hasFreeEmail=",hasFreeEmail))[,c("issuesReported", "issuesResolved")]))
}

printDivider <- function() {
    print(paste(replicate(80,"-"), collapse=""))
}

getDBConnection <- function(dbtype, ...) {
    if (missing(dbtype)) dbConnect(SQLite(), "sqlite.db") else dbConnect(dbtype, ...)
}

analyzeData <- function(dbtype, ...) {
    dbConnection <- getDBConnection(dbtype, ...)
    
    reportedByVolunteer <- dbGetQuery(dbConnection, "select contributors.\"hasFreeEmail\" as reportedByVolunteer from issues inner join contributors on issues.reporter_id=contributors.id")
    resolvedByVolunteer <- dbGetQuery(dbConnection, "select contributors.\"hasFreeEmail\" as resolvedByVolunteer from issues inner join contributors on issues.resolver_id=contributors.id")

    contributors <- dbGetQuery(dbConnection, "select * from contributors")
    summaryCols <- c("issuesReported", "issuesResolved")
    topTableCols <- c("email", "issuesReported", "issuesResolved")
    contributorTypes <- c("employees", "volunteers")
    
    showDataFor <- function(contributorClass) {
        printDivider()
        contributorClassName <- contributorTypes[contributorClass+1]
        print(paste("Data for ", contributorClassName, ":", sep = ""))
        classReportCount <- length(reportedByVolunteer[reportedByVolunteer == contributorClass])
        classResolveCount <- length(resolvedByVolunteer[resolvedByVolunteer == contributorClass])
        print(paste(contributorClassName, "reported", classReportCount, "issues"))
        print(paste(contributorClassName, "resolved", classResolveCount, "issues"))
        contributorsOfClass <- contributors[contributors$hasFreeEmail==contributorClass, summaryCols]
        print(paste("summary for ", contributorClassName, ":", sep = ""))
        print(summary(contributorsOfClass))
        print(paste("sd:", sd(contributorsOfClass[,"issuesReported"]), "sd:", sd(contributorsOfClass[,"issuesResolved"])))
        print("Top 10 reporters:")
        print(contributors[contributors$hasFreeEmail==contributorClass, topTableCols][order(contributorsOfClass$issuesReported, decreasing = TRUE)[1:10],])
        print("Top 10 resolvers:")
        print(contributors[contributors$hasFreeEmail==contributorClass, topTableCols][order(contributorsOfClass$issuesResolved, decreasing = TRUE)[1:10],])
    }
    
    lapply(c(0,1), showDataFor)
    
    printDivider()
    print("Current count of issues at each priority level, grouped by reporter class:")
    priorityLevels <- c("Blocker", "Critical", "Major", "Minor", "Trivial")
    priorityReportedByVolunteerTable <- dbGetQuery(dbConnection, "select issues.\"currentPriority\", contributors.\"hasFreeEmail\" as \"reportedByVolunteer\" from issues inner join contributors on issues.reporter_id=contributors.id")
    getIssueCountByReporters <- function(priority, reportedByVolunteer) {
        nrow(priorityReportedByVolunteerTable[priorityReportedByVolunteerTable$currentPriority == priority & priorityReportedByVolunteerTable$reportedByVolunteer == reportedByVolunteer,])
    }
    priorityTable <- outer(priorityLevels, c(FALSE, TRUE), Vectorize(getIssueCountByReporters))
    rownames(priorityTable) <- priorityLevels
    colnames(priorityTable) <- contributorTypes
    print(priorityTable)
    
    printDivider()
    print("Current count of resolved issues at each priority level, grouped by resolver class:")
    priorityResolvedByVolunteerTable <- dbGetQuery(dbConnection, "select issues.\"currentPriority\", contributors.\"hasFreeEmail\" as \"resolvedByVolunteer\" from issues inner join contributors on issues.resolver_id=contributors.id")
    getIssueCountByResolvers <- function(priority, resolvedByVolunteer) {
        nrow(priorityResolvedByVolunteerTable[priorityResolvedByVolunteerTable$currentPriority == priority & priorityResolvedByVolunteerTable$resolvedByVolunteer == resolvedByVolunteer,])
    }
    priorityTable <- outer(priorityLevels, c(FALSE, TRUE), Vectorize(getIssueCountByResolvers))
    rownames(priorityTable) <- priorityLevels
    colnames(priorityTable) <- contributorTypes
    print(priorityTable)
    
    invisible(dbDisconnect(dbConnection))
}

getProjectContributors <- function(project) {
    dbGetQuery(dbConnection, paste("select distinct contributors.id from contributors inner join contributoraccounts ca on contributors.id=ca.contributors_id inner join accountprojects on ca.id=accountprojects.contributoraccounts_id where upper(project)=upper('", project, "')", sep=""))$id
}

buildFeatureTable <- function(project) {
    # generates functions for computing feature values in the context of this project
    featureQueryClosure <- function(featureClause) {
        featureEvaluator <- function(contributorId) {
            dbGetQuery(dbConnection, paste("select count(*) from contributoraccounts inner join accountprojects on contributoraccounts.id=accountprojects.contributoraccounts_id where contributors_id=", contributorId, " and ", featureClause, " and upper(project)=upper('", project, "');", sep=""))$count > 0
        }
        attr(featureEvaluator, "featureClause") <- featureClause
        featureEvaluator
    }
    
    # generate vector of functions which compute feature values for a given contributorId
    featureEvaluators <- sapply(c(
        "\"hasCommercialEmail\"=True",
        "\"hasRelatedCompanyEmail\"=True",
        "\"hasRelatedEmployer\"=True",
        "\"isRelatedOrgMember\"=True",
        "\"isRelatedProjectCommitter\"=True",
        "\"BHCommitCount\">\"NonBHCommitCount\""), featureQueryClosure)
    
    projectContributors <- getProjectContributors(project)
    
    # returns a list of feature values for a given feature evaluator applied to all contributors
    getFeatureValues <- function(featureEvaluator) {
        vapply(projectContributors, featureEvaluator, TRUE)
    }
    
    # construct the feature table by applying getFeatureValues to each evaluator, and merging these results as columns
    featureTable <- do.call(cbind.data.frame, append(list(projectContributors), lapply(featureEvaluators, getFeatureValues)))
    colnames(featureTable) <- c("contributorId", sapply(featureEvaluators, attr, "featureClause"))
    featureTable
}

printClassificationWorksheet <- function(project) {
    identifyingData <- dbGetQuery(dbConnection, paste("select contributors.id as \"contributorId\", \"ghLogin\", username, \"displayName\", email from contributors inner join contributoraccounts on contributors.id=contributoraccounts.contributors_id where contributors.id in (select distinct contributors.id from contributors inner join contributoraccounts ca on contributors.id=ca.contributors_id inner join accountprojects on ca.id=accountprojects.contributoraccounts_id where upper(project)=upper('", project, "')) order by \"contributorId\" asc", sep=""))
    identifyingData$isCommercial <- NA
    write.csv(identifyingData, file=paste(project, "worksheet.csv", sep=""), row.names=FALSE)
}

classifyContributors <- function(project) {
    # get golden set from classification worksheet
    worksheet <- read.csv(paste(project, "worksheet.csv", sep = ""))
    trainingContributors <- worksheet[!is.na(worksheet$isCommercial),c("contributorId", "isCommercial")]
    featureTable <- buildFeatureTable(project)+0
    classifiedTable <- merge(featureTable, trainingContributors, by="contributorId")
    trainingSet <- classifiedTable[,-1]
    model <- naiveBayes(as.factor(isCommercial) ~ ., data=trainingSet)
    predict(model, featureTable[,-1]+0)
}