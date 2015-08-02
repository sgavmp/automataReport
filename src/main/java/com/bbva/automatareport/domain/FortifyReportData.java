package com.bbva.automatareport.domain;

import java.util.List;
import java.util.Map;

public class FortifyReportData {
	private List<String> listOfFiles;
	private String resumeScan;
	private Map<Level,List<VulnerabilityResume>> vulnerabilitiesDetectedResume;
	private Map<Level,List<VulnerabilityDetails>> vulnerabilitiesDetectedDetails;
	public List<String> getListOfFiles() {
		return listOfFiles;
	}
	public void setListOfFiles(List<String> listOfFiles) {
		this.listOfFiles = listOfFiles;
	}
	public String getResumeScan() {
		return resumeScan;
	}
	public void setResumeScan(String resumeScan) {
		this.resumeScan = resumeScan;
	}
	public Map<Level, List<VulnerabilityResume>> getVulnerabilitiesDetectedResume() {
		return vulnerabilitiesDetectedResume;
	}
	public void setVulnerabilitiesDetectedResume(
			Map<Level, List<VulnerabilityResume>> vulnerabilitiesDetectedResume) {
		this.vulnerabilitiesDetectedResume = vulnerabilitiesDetectedResume;
	}
	public Map<Level, List<VulnerabilityDetails>> getVulnerabilitiesDetectedDetails() {
		return vulnerabilitiesDetectedDetails;
	}
	public void setVulnerabilitiesDetectedDetails(
			Map<Level, List<VulnerabilityDetails>> vulnerabilitiesDetectedDetails) {
		this.vulnerabilitiesDetectedDetails = vulnerabilitiesDetectedDetails;
	}
	@Override
	public String toString() {
		return "FortifyReportData [listOfFiles=" + listOfFiles
				+ ", resumeScan=" + resumeScan
				+ ", vulnerabilitiesDetectedResume="
				+ vulnerabilitiesDetectedResume
				+ ", vulnerabilitiesDetectedDetails="
				+ vulnerabilitiesDetectedDetails + "]";
	}
	
	
	
	
}
