library(network)
library(sna)

doQuery <- function(query) {
    dbGetQuery(dbConnection, query)
}

getTable <- function(tableName) {
    doQuery(paste("select * from", tableName, ";"))
}

getContributorCompanies <- function() {
    getTable("contributorcompanies")
}

getContributorProjectCommitCount <- function() {
    getTable("contributorprojectcommitcount")
}

getContributorCompanyProjectCommitCount <- function() {
    doQuery("select * from contributorcompanies cc inner join contributorprojectcommitcount cpcc on cc.contributors_id=cpcc.id")
}

getCompanyEdgeList <- function() {
    doQuery("select cpcc1.company as company1, cpcc2.company as company2, cpcc1.commitcount+cpcc2.commitcount as combinedcommitcount from companyprojectcommitcount cpcc1 inner join companyprojectcommitcount cpcc2 on cpcc1.project=cpcc2.project where cpcc1.company != cpcc2.company;")
}

getCompanyNetwork <- function() {
    network(getCompanyEdgeList(), directed = FALSE, matrix.type = "edgelist")
}