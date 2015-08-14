package com.bbva.automatareport.domain;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import com.bbva.automatareport.util.MD5EncryptUtil;

public class Issue {
	private String category;
	private String folder;
	private String priority;
	private String kingdom;
	private String abstractI;
	private String analysis;
	private String file;
	private String path;
	private Integer lineStart;
	private String snippet;
	private List<IssueLine> lines;
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
	public String getPriority() {
		return priority;
	}
	public void setPriority(String friority) {
		this.priority = friority;
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
		List<IssueLine> lineas = new ArrayList<IssueLine>();
		String[] stringLineas = snippet.split("\n");
		Integer num = stringLineas.length;
		Integer half = -( num / 2);
		for (int i = 0; i<num; i++) {
			lineas.add(new IssueLine(lineStart + half, stringLineas[i], (half==0?true:false)) );
			half++;
		}
		lines = lineas;
	}
	
	public List<IssueLine> getLines() {
		return lines;
	}
	
	
	public void setLines(List<IssueLine> lines) {
		this.lines = lines;
	}
	
	
	public String getPath() {
		return path;
	}
	public void setPath(String path) {
		this.path = path;
	}
	
	public String getId() {
		String resumen = category.trim().concat(path.trim()).concat(snippet.trim());
		return MD5EncryptUtil.cryptMD5(resumen).substring(24, 31);
	}
	@Override
	public String toString() {
		return "Issue [category=" + category + ", folder=" + folder
				+ ", friority=" + priority + ", kingdom=" + kingdom
				+ ", abstractI=" + abstractI + ", analysis=" + analysis
				+ ", file=" + file + ", lineStart=" + lineStart + ", snippet="
				+ snippet + "]";
	}
	
	
}
