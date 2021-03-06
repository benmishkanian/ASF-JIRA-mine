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
    
    customFeatureQueryClosure <- function(queryHead, queryTail, featureName) {
        featureEvaluator <- function(contributorId) {
            result <- dbGetQuery(dbConnection, paste(queryHead, contributorId, queryTail, sep = ""))
            if (nrow(result) == 0) -1 else result[,1]
        }
        attr(featureEvaluator, "featureClause") <- featureName
        featureEvaluator
    }
    
    BHCommitCountEvaluator <- function(contributorId) {
        dbGetQuery(dbConnection, paste("select sum(\"BHCommitCount\") as \"BHCommitCountSum\" from contributoraccounts inner join accountprojects on contributoraccounts.id=accountprojects.contributoraccounts_id where contributors_id=", contributorId, " and upper(project)=upper('", project, "');", sep=""))$BHCommitCountSum
    }
    
    # generate vector of functions which compute feature values for a given contributorId
    featureEvaluators <- sapply(c(
        "\"hasCommercialEmail\"=True",
        "\"hasRelatedCompanyEmail\"=True",
        "\"hasRelatedEmployer\"=True",
        "\"isRelatedOrgMember\"=True",
        "\"isRelatedProjectCommitter\"=True"), featureQueryClosure)
    
    customFeatureEvaluators <- c(
        customFeatureQueryClosure("select sum(\"BHCommitCount\") as \"BHCommitCountSum\" from contributoraccounts inner join accountprojects on contributoraccounts.id=accountprojects.contributoraccounts_id where contributors_id=", paste(" and upper(project)=upper('", project, "');", sep=""), "BHCommitCountSum"),
        customFeatureQueryClosure("select sum(\"NonBHCommitCount\") as \"NonBHCommitCount\" from contributoraccounts inner join accountprojects on contributoraccounts.id=accountprojects.contributoraccounts_id where contributors_id=", paste(" and upper(project)=upper('", project, "');", sep=""), "NonBHCommitCountSum"),
        customFeatureQueryClosure(paste("select domaincount from (select domain, count(domain) as domaincount from (select domain, contributors_id from contributoraccounts inner join accountprojects on contributoraccounts.id=accountprojects.contributoraccounts_id where (domain <> '') is True and \"hasCommercialEmail\"=True and project='", project, "' group by contributors_id, domain) as subq group by domain) subq2 where exists ( select distinct domain from contributoraccounts where contributors_id=", sep=""), " and (domain <> '') is True and domain=subq2.domain) order by domaincount desc limit 1;", "domaincount")
        )
    
    featureEvaluators <- c(featureEvaluators, customFeatureEvaluators)
    
    projectContributors <- getProjectContributors(project)
    
    # returns a list of feature values for a given feature evaluator applied to all contributors
    getFeatureValues <- function(featureEvaluator) {
        sapply(projectContributors, featureEvaluator)
    }
    
    # construct the feature table by applying getFeatureValues to each evaluator, and merging these results as columns
    featureTable <- do.call(cbind.data.frame, append(list(projectContributors), lapply(featureEvaluators, getFeatureValues)))
    colnames(featureTable) <- c("contributorId", sapply(featureEvaluators, attr, "featureClause"))
    featureTable
}

rankProjectsByCommercialization <- function() {
    projectVector <- getMinedProjects()
    getCommercializationScore <- function(project) {
        mean(rowSums((buildFeatureTable(project)+0)[,-1]))
    }
    commercializationScores <- sapply(projectVector, getCommercializationScore)
    scoreTable <- data.frame(projectVector, commercializationScores)
    scoreTable[order(commercializationScores),]
}

printClassificationWorksheet <- function(project) {
    identifyingData <- dbGetQuery(dbConnection, paste("select contributors.id as \"contributorId\", \"ghLogin\", username, \"displayName\", email from contributors inner join contributoraccounts on contributors.id=contributoraccounts.contributors_id where contributors.id in (select distinct contributors.id from contributors inner join contributoraccounts ca on contributors.id=ca.contributors_id inner join accountprojects on ca.id=accountprojects.contributoraccounts_id where upper(project)=upper('", project, "')) order by \"contributorId\" asc", sep=""))
    identifyingData$isCommercial <- NA
    write.csv(identifyingData, file=paste(project, "worksheet.csv", sep=""), row.names=FALSE)
}

naiveBayesPrediction <- function(trainingSet, newData) {
    predict(naiveBayes(as.factor(isCommercial) ~ ., data=trainingSet), newData)
}

classifyContributors <- function(project) {
    # get golden set from classification worksheet
    worksheet <- read.csv(paste(project, "worksheet.csv", sep = ""))
    # refresh contributor IDs, in case database changed
    worksheet$contributorId <- mapply(getContributorID, worksheet$ghLogin, worksheet$username)
    trainingContributors <- worksheet[!is.na(worksheet$isCommercial),c("contributorId", "isCommercial")]
    featureTable <- buildFeatureTable(project)+0
    classifiedTable <- merge(featureTable, trainingContributors, by="contributorId")
    trainingSet <- classifiedTable[,-1]
    naiveBayesPrediction(trainingSet, featureTable[,-1]+0)
}

getContributorID <- function(ghUsername, otherUsername) {
    if (!is.na(ghUsername)) {
        dbGetQuery(dbConnection, paste("select id from contributors where \"ghLogin\"='", ghUsername, "'", sep = ""))$id
    } 
    else {
        dbGetQuery(dbConnection, paste("select contributors.id from contributors inner join contributoraccounts on contributors.id=contributors_id where username='", otherUsername, "'", sep = ""))$id
    }
}

getMinedProjects <- function() {
    dbGetQuery(dbConnection, "select distinct project from accountprojects;")$project
}

writeFeatureTables <- function(projects) {
    sapply(projects, function(project)write.csv(buildFeatureTable(project), paste(project, ".csv", sep = ""), row.names = FALSE))
}

getContributorRows <- function(contributorID) {
    queryDatabase(paste("select * from contributors inner join contributoraccounts ca on contributors.id=ca.contributors_id inner join accountprojects ap on ca.id=ap.contributoraccounts_id where contributors.id=", contributorID, sep = ""))
}

getRowsForContributors <- function(contributorIDs) {
    do.call(rbind.data.frame, lapply(contributorIDs, getContributorRows))
}

getTop10Contributors <- function(tableFile) {
    csvFile <- read.csv(tableFile)
    filteredTable <- csvFile[csvFile$BHCommitCountSum + csvFile$NonBHCommitCountSum > 0,]
    topContributors <- filteredTable[order(filteredTable$BHCommitCountSum + filteredTable$NonBHCommitCountSum, decreasing = TRUE), "contributorId"][1:10]
    if (length(topContributors[is.na(topContributors)]) > 0) {
        print(tableFile)
    }
    topContributors
}

getProjectDataPath <- function(project) {
    paste("contributorData/", project, ".csv", sep = "")
}

getTopContributorsForProjects <- function(projects) {
    projectPaths <- sapply(projects, getProjectDataPath)
    listsOfTopContributors <- sapply(projectPaths, getTop10Contributors)
    c(listsOfTopContributors)
}