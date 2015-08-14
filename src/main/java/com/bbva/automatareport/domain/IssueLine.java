package com.bbva.automatareport.domain;

public class IssueLine {
	public Integer numberLine;
	public String stringLine;
	public boolean isCenter;
	
	public IssueLine(Integer numberLine, String stringLine, boolean isCenter) {
		super();
		this.numberLine = numberLine;
		this.stringLine = stringLine;
		this.isCenter = isCenter;
	}
	public Integer getNumberLine() {
		return numberLine;
	}
	public void setNumberLine(Integer numberLine) {
		this.numberLine = numberLine;
	}
	public String getStringLine() {
		return stringLine;
	}
	public void setStringLine(String stringLine) {
		this.stringLine = stringLine;
	}
	public boolean getIsCenter() {
		return isCenter;
	}
	public void setCenter(boolean isCenter) {
		this.isCenter = isCenter;
	}
	
}
