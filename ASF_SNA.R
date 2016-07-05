library(network)

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