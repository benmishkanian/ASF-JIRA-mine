library(network)
library(sna)
library(igraph)

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

# Returns a data frame showing the total (Freeman) degree of each company
getDegreeCentrality <- function(companyNetwork) {
    cbind.data.frame(get.vertex.attribute(cn, "vertex.names"), degree(companyNetwork, gmode="graph", diag = TRUE))
}

# Returns a data frame showing the standard undirected betweenness of each company, ignoring edge values
getBetweennessCentrality <- function(companyNetwork) {
    cbind.data.frame(get.vertex.attribute(cn, "vertex.names"), betweenness(companyNetwork, gmode="graph", diag = TRUE, cmode = "undirected"))
}

# Returns a data frame showing the undirected closeness of each company, ignoring edge values
getClosenessCentrality <- function(companyNetwork) {
    cbind.data.frame(get.vertex.attribute(cn, "vertex.names"), closeness(companyNetwork, gmode = "graph", diag = TRUE, cmode = "undirected"))
}

getCentralities <- function(companyNetwork){
    getCentrality <- function(centralityFun) {
        ranking <- ranked(centralityFun(companyNetwork))
        colnames(ranking) <- c("organization", "score")
        ranking
    }
    lapply(c(getDegreeCentrality, getBetweennessCentrality, getClosenessCentrality), getCentrality)
}

getCentralization <- function(companyNetwork, centralityFunction) {
    centralization(companyNetwork, centralityFunction, mode = "graph", diag = TRUE)
}

ranked <- function(centralityTable) {
    centralityTable[order(-centralityTable[,2]),]
}

performGirvanNewman <- function(edgelist) {
    # generate igraph
	ig <- graph_from_edgelist(edgelist, directed = FALSE)
	# assign vertex weights based on number of contributors
	getContributorCount <- function(organization) {
	    # assumes that contributorcompanies contains exactly the set of contributors whose contributions are reflected in ig
        doQuery(paste("select count(*) from contributorcompanies where company='", organization, "';")
	}
	setVertexWeight <- function(vertex, ig) {
	    set.vertex.attribute(ig, "weight", vertex, getContributorCount(get.vertex.attribute(ig, "name", vertex)))
	}
	vertices <- V(ig)
	for (vertex in vertices) {
	    ig <- setVertexWeight(vertex, ig)
	}
	ig <- set.vertex.attribute(ig, "weight")
    orgCommunities <- edge.betweenness.community(ig, directed = FALSE)
	plot(orgCommunities, ig)
}