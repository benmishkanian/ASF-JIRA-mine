library(network)
library(sna)

# dbConnection should be bound to a PostgreSQL connection
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
    doQuery("
            BEGIN;
            CREATE TEMP TABLE tempedgelist ON COMMIT DROP as select cpcc1.company as company1, cpcc2.company as company2, cpcc1.commitcount+cpcc2.commitcount as combinedcommitcount from companyprojectcommitcount cpcc1 inner join companyprojectcommitcount cpcc2 on cpcc1.project=cpcc2.project where cpcc1.company != cpcc2.company and (cpcc1.commitcount > 0 or cpcc2.commitcount > 0);
            DELETE FROM tempedgelist te1 using tempedgelist te2 WHERE te1.company1=te2.company2 and te1.company2=te2.company1 and te1.ctid < te2.ctid;
            ")
    result <- doQuery("SELECT * FROM tempedgelist;")
    doQuery("END;")
    result
}

getCompanyNetwork <- function() {
    network(getCompanyEdgeList(), directed = FALSE, matrix.type = "edgelist")
}