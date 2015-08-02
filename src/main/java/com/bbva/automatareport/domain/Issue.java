package com.bbva.automatareport.domain;

public class Issue {

	private String category;
	private String folder;
	private String friority;
	private String kingdom;
	private String abstractI;
	private String analysis;
	private String file;
	private Integer lineStart;
	private String snippet;
	public String getCategory() {
		return category;
	}
	public void setCategory(String category) {
		this.category = category;
	}
	public String getFolder() {
		return folder;
	}
	public void setFolder(String folder) {
		this.folder = folder;
	}
	public String getFriority() {
		return friority;
	}
	public void setFriority(String friority) {
		this.friority = friority;
	}
	public String getKingdom() {
		return kingdom;
	}
	public void setKingdom(String kingdom) {
		this.kingdom = kingdom;
	}
	public String getAbstractI() {
		return abstractI;
	}
	public void setAbstractI(String abstractI) {
		this.abstractI = abstractI;
	}
	public String getAnalysis() {
		return analysis;
	}
	public void setAnalysis(String analysis) {
		this.analysis = analysis;
	}
	public String getFile() {
		return file;
	}
	public void setFile(String file) {
		this.file = file;
	}
	public Integer getLineStart() {
		return lineStart;
	}
	public void setLineStart(Integer lineStart) {
		this.lineStart = lineStart;
	}
	public String getSnippet() {
		return snippet;
	}
	public void setSnippet(String snippet) {
		this.snippet = snippet;
	}
	@Override
	public String toString() {
		return "Issue [category=" + category + ", folder=" + folder
				+ ", friority=" + friority + ", kingdom=" + kingdom
				+ ", abstractI=" + abstractI + ", analysis=" + analysis
				+ ", file=" + file + ", lineStart=" + lineStart + ", snippet="
				+ snippet + "]";
	}
	
	
}
