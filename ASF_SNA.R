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
            CREATE TEMP TABLE tempedgelist ON COMMIT DROP as select cpcc1.company as company1, cpcc2.company as company2, cpcc1.commitcount+cpcc2.commitcount as paircommitcount, cpcc1.project from companyprojectcommitcount cpcc1 inner join companyprojectcommitcount cpcc2 on cpcc1.project=cpcc2.project where cpcc1.company != cpcc2.company and (cpcc1.commitcount > 0 or cpcc2.commitcount > 0);
            DELETE FROM tempedgelist te1 using tempedgelist te2 WHERE te1.company1=te2.company2 and te1.company2=te2.company1 and te1.project = te2.project and te1.ctid < te2.ctid;
            CREATE TEMP TABLE switchedrows2 ON COMMIT DROP as select * from tempedgelist tf2 where exists (select 1 from tempedgelist tf2a where tf2.company1=tf2a.company2 and tf2.company2=tf2a.company1 and tf2.ctid<tf2a.ctid);
            delete from tempedgelist tf2 where exists (select 1 from tempedgelist tf2a where tf2.company1=tf2a.company2 and tf2.company2=tf2a.company1 and tf2.ctid<tf2a.ctid);
            UPDATE tempedgelist tel SET paircommitcount=tel.paircommitcount+sr.paircommitcount FROM switchedrows2 sr WHERE tel.company1=sr.company2 and tel.company2=sr.company1;
            ")
    result <- doQuery("SELECT company1, company2, sum(paircommitcount) as combinedcommitcount FROM tempedgelist group by company1, company2;")
    doQuery("END;")
    result
}

getCompanyNetwork <- function() {
    network(getCompanyEdgeList(), directed = FALSE, matrix.type = "edgelist")
}

# Returns a data frame showing the total (Freeman) degree of each company
getDegreeCentrality <- function(companyNetwork) {
    cbind.data.frame(get.vertex.attribute(companyNetwork, "vertex.names"), degree(companyNetwork, gmode="graph", diag = TRUE))
}

# Returns a data frame showing the standard undirected betweenness of each company, ignoring edge values
getBetweennessCentrality <- function(companyNetwork) {
    cbind.data.frame(get.vertex.attribute(companyNetwork, "vertex.names"), betweenness(companyNetwork, gmode="graph", diag = TRUE, cmode = "undirected"))
}

# Returns a data frame showing the undirected closeness of each company, ignoring edge values
getClosenessCentrality <- function(companyNetwork) {
    cbind.data.frame(get.vertex.attribute(companyNetwork, "vertex.names"), closeness(companyNetwork, gmode = "graph", diag = TRUE, cmode = "undirected"))
}

# TODO: Why does setting ignore.eval=TRUE not affect the results?

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

unloadigraph <- function() {
    detach("package:igraph", unload = TRUE)
}

## Functions below this line require library(igraph) ##

makeiGraph <- function(edgelist) {
    edgelist <- as.matrix(edgelist[,-3])
    ig <- graph_from_edgelist(edgelist, directed = FALSE)
    # assign vertex weights based on number of contributors
    getContributorCount <- function(organization) {
        # assumes that contributorcompanies contains exactly the set of contributors whose contributions are reflected in ig
        doQuery(paste("select count(*) from contributorcompanies where company='", organization, "';", sep = ""))
    }
    setVertexWeight <- function(vertex, ig) {
        set.vertex.attribute(ig, "weight", vertex, getContributorCount(get.vertex.attribute(ig, "name", vertex)))
    }
    vertices <- V(ig)
    for (vertex in vertices) {
        ig <- setVertexWeight(vertex, ig)
    }
    ig
}

# takes igraph as input
performGirvanNewman <- function(ig) {
    orgCommunities <- edge.betweenness.community(ig, directed = FALSE)
}

outputCommunitiesPlot <- function(orgCommunities, ig, outFile) {
    png(file = outFile, width=1700,height=2200);
    par(mar = c(0,0,0,0))
    plot(orgCommunities, ig, vertex.size = unlist(V(ig)$weight), layout=layout.lgl, asp = 1.294)
    dev.off()
}