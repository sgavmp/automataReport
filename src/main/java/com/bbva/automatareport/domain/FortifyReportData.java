package com.bbva.automatareport.domain;

import java.util.List;

public class FortifyReportData {
	private String applicationName;
	private String applicationCode;
	private List<String> listOfFiles;
	private String numFiles;
	private String numLines;
	private List<VulnerabilityResume> vulnerabilitiesCriticDetectedResume;
	private List<VulnerabilityDetails> vulnerabilitiesCriticDetectedDetails;
	private List<VulnerabilityResume> vulnerabilitiesHighDetectedResume;
	private List<VulnerabilityDetails> vulnerabilitiesHighDetectedDetails;
	private List<VulnerabilityResume> vulnerabilitiesMediumDetectedResume;
	private List<VulnerabilityDetails> vulnerabilitiesMediumDetectedDetails;
	private List<VulnerabilityResume> vulnerabilitiesLowDetectedResume;
	private List<VulnerabilityDetails> vulnerabilitiesLowDetectedDetails;
	private Integer numCritic;
	private Integer numHigh;
	private Integer numMedium;
	private Integer numLow;
	public void calculateNumOfVulenrabilities() {
		numCritic=0;
		numHigh=0;
		numMedium=0;
		numLow=0;
		for (VulnerabilityResume resume : vulnerabilitiesCriticDetectedResume) {
			numCritic+=resume.getCount();
		}
		for (VulnerabilityResume resume : vulnerabilitiesHighDetectedResume) {
			numHigh+=resume.getCount();
		}
		for (VulnerabilityResume resume : vulnerabilitiesMediumDetectedResume) {
			numMedium+=resume.getCount();
		}
		for (VulnerabilityResume resume : vulnerabilitiesLowDetectedResume) {
			numLow+=resume.getCount();
		}
	}
	public List<String> getListOfFiles() {
		return listOfFiles;
	}
	public void setListOfFiles(List<String> listOfFiles) {
		this.listOfFiles = listOfFiles;
	}	
	public String getNumFiles() {
		return numFiles;
	}
	public void setNumFiles(String numFiles) {
		this.numFiles = numFiles;
	}
	public String getNumLines() {
		return numLines;
	}
	public void setNumLines(String numLines) {
		this.numLines = numLines;
	}
	public String getApplicationName() {
		return applicationName;
	}
	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}
	public String getApplicationCode() {
		return applicationCode;
	}
	public void setApplicationCode(String applicationCode) {
		this.applicationCode = applicationCode;
	}
	public List<VulnerabilityResume> getVulnerabilitiesCriticDetectedResume() {
		return vulnerabilitiesCriticDetectedResume;
	}
	public void setVulnerabilitiesCriticDetectedResume(List<VulnerabilityResume> vulnerabilitiesCriticDetectedResume) {
		this.vulnerabilitiesCriticDetectedResume = vulnerabilitiesCriticDetectedResume;
	}
	public List<VulnerabilityDetails> getVulnerabilitiesCriticDetectedDetails() {
		return vulnerabilitiesCriticDetectedDetails;
	}
	public void setVulnerabilitiesCriticDetectedDetails(List<VulnerabilityDetails> vulnerabilitiesCriticDetectedDetails) {
		this.vulnerabilitiesCriticDetectedDetails = vulnerabilitiesCriticDetectedDetails;
	}
	public List<VulnerabilityResume> getVulnerabilitiesHighDetectedResume() {
		return vulnerabilitiesHighDetectedResume;
	}
	public void setVulnerabilitiesHighDetectedResume(List<VulnerabilityResume> vulnerabilitiesHighDetectedResume) {
		this.vulnerabilitiesHighDetectedResume = vulnerabilitiesHighDetectedResume;
	}
	public List<VulnerabilityDetails> getVulnerabilitiesHighDetectedDetails() {
		return vulnerabilitiesHighDetectedDetails;
	}
	public void setVulnerabilitiesHighDetectedDetails(List<VulnerabilityDetails> vulnerabilitiesHighDetectedDetails) {
		this.vulnerabilitiesHighDetectedDetails = vulnerabilitiesHighDetectedDetails;
	}
	public List<VulnerabilityResume> getVulnerabilitiesMediumDetectedResume() {
		return vulnerabilitiesMediumDetectedResume;
	}
	public void setVulnerabilitiesMediumDetectedResume(List<VulnerabilityResume> vulnerabilitiesMediumDetectedResume) {
		this.vulnerabilitiesMediumDetectedResume = vulnerabilitiesMediumDetectedResume;
	}
	public List<VulnerabilityDetails> getVulnerabilitiesMediumDetectedDetails() {
		return vulnerabilitiesMediumDetectedDetails;
	}
	public void setVulnerabilitiesMediumDetectedDetails(List<VulnerabilityDetails> vulnerabilitiesMediumDetectedDetails) {
		this.vulnerabilitiesMediumDetectedDetails = vulnerabilitiesMediumDetectedDetails;
	}
	public List<VulnerabilityResume> getVulnerabilitiesLowDetectedResume() {
		return vulnerabilitiesLowDetectedResume;
	}
	public void setVulnerabilitiesLowDetectedResume(List<VulnerabilityResume> vulnerabilitiesLowDetectedResume) {
		this.vulnerabilitiesLowDetectedResume = vulnerabilitiesLowDetectedResume;
	}
	public List<VulnerabilityDetails> getVulnerabilitiesLowDetectedDetails() {
		return vulnerabilitiesLowDetectedDetails;
	}
	public void setVulnerabilitiesLowDetectedDetails(List<VulnerabilityDetails> vulnerabilitiesLowDetectedDetails) {
		this.vulnerabilitiesLowDetectedDetails = vulnerabilitiesLowDetectedDetails;
	}
	public Integer getNumCritic() {
		return numCritic;
	}
	public void setNumCritic(Integer numCritic) {
		this.numCritic = numCritic;
	}
	public Integer getNumHigh() {
		return numHigh;
	}
	public void setNumHigh(Integer numHigh) {
		this.numHigh = numHigh;
	}
	public Integer getNumMedium() {
		return numMedium;
	}
	public void setNumMedium(Integer numMedium) {
		this.numMedium = numMedium;
	}
	public Integer getNumLow() {
		return numLow;
	}
	public void setNumLow(Integer numLow) {
		this.numLow = numLow;
	}	
	
	
	
}
