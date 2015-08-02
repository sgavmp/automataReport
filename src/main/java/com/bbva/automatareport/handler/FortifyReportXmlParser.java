package com.bbva.automatareport.handler;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import com.bbva.automatareport.domain.FortifyReportData;
import com.bbva.automatareport.domain.Issue;
import com.bbva.automatareport.domain.Level;
import com.bbva.automatareport.domain.VulnerabilityDetails;
import com.bbva.automatareport.domain.VulnerabilityResume;

public class FortifyReportXmlParser extends DefaultHandler {
	private FortifyReportData data;
	
	public FortifyReportXmlParser() {
		data = new FortifyReportData();
	}
	
	public void parser() {
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory
					.newInstance();
			DocumentBuilder builder;
			builder = factory.newDocumentBuilder();
			Document doc = builder.parse(ClassLoader.getSystemResource("xml/RC_PALTA_VAR-17OCT2014_01_-_Fortify_Scan_Summary.xml").getFile());
			XPathFactory xPathfactory = XPathFactory.newInstance();
			XPath xpath = xPathfactory.newXPath();
			//Lista de ficheros analizados
			XPathExpression expr = xpath.compile("/ReportDefinition/ReportSection[Title='Detailed Project Summary']/SubSection[Title='Files Scanned']/Text");
			String files = (String)expr.evaluate(doc, XPathConstants.STRING);
			Matcher m = Pattern.compile("(?m)^[\\w\\s]+\\.\\w+").matcher(files);
			data.setListOfFiles(new ArrayList<String>());
			while (m.find()) {
			   data.getListOfFiles().add(m.group());
			}
			////Resumen ejecutivo
			doc = builder.parse(ClassLoader.getSystemResource("xml/RC_PALTA_VAR-17OCT2014_01_-_Informe_ejecutivo.xml").getFile());
			//Resumen del escaneo
			expr = xpath.compile("/ReportDefinition/ReportSection[Title='Report Overview']/SubSection[Title='Resumen del escaneo']/Text");
			data.setResumeScan((String)expr.evaluate(doc, XPathConstants.STRING));
			//Resumen de vulnerabilidades detectadas
			//Nivel critico
			expr = xpath.compile("count(//ReportDefinition/ReportSection[Title='Vulnerabilidades']/SubSection[Title='Tabla de vulnerabilidades nivel crítico']/IssueListing/Chart/GroupingSection)");
			Integer numCriticas = Integer.parseInt((String)expr.evaluate(doc, XPathConstants.STRING));
			Map<String,Integer> vunerabilidadesCriticas = new HashMap<String, Integer>();
			expr = xpath.compile("//ReportDefinition/ReportSection[Title='Vulnerabilidades']/SubSection[Title='Tabla de vulnerabilidades nivel crítico']/IssueListing/Chart/GroupingSection");
			NodeList listaVun = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			List<VulnerabilityResume> resumesCritic = new ArrayList<VulnerabilityResume>();
			for (int i=0;i<numCriticas;i++) {
				Integer countVun = Integer.parseInt(listaVun.item(i).getAttributes().getNamedItem("count").getNodeValue());
				String nameVun = listaVun.item(i).getTextContent().trim();
				vunerabilidadesCriticas.put(nameVun, countVun);
				VulnerabilityResume temp = new VulnerabilityResume();
				temp.setCount(countVun);
				temp.setLevel(Level.CRITIC);
				temp.setName(nameVun);
				resumesCritic.add(temp);
			}
			//Nivel alto
			expr = xpath.compile("count(//ReportDefinition/ReportSection[Title='Vulnerabilidades']/SubSection[Title='Tabla de vulnerabilidades nivel alto']/IssueListing/Chart/GroupingSection)");
			Integer numAltas = Integer.parseInt((String)expr.evaluate(doc, XPathConstants.STRING));
			Map<String,Integer> vunerabilidadesAltas = new HashMap<String, Integer>();
			expr = xpath.compile("//ReportDefinition/ReportSection[Title='Vulnerabilidades']/SubSection[Title='Tabla de vulnerabilidades nivel alto']/IssueListing/Chart/GroupingSection");
			listaVun = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			List<VulnerabilityResume> resumesHigh = new ArrayList<VulnerabilityResume>();
			for (int i=0;i<numAltas;i++) {
				Integer countVun = Integer.parseInt(listaVun.item(i).getAttributes().getNamedItem("count").getNodeValue());
				String nameVun = listaVun.item(i).getTextContent().trim();
				vunerabilidadesAltas.put(nameVun, countVun);
				VulnerabilityResume temp = new VulnerabilityResume();
				temp.setCount(countVun);
				temp.setLevel(Level.HIGH);
				temp.setName(nameVun);
				resumesHigh.add(temp);
			}
			//Nivel medio
			expr = xpath.compile("count(//ReportDefinition/ReportSection[Title='Vulnerabilidades']/SubSection[Title='Tabla de vulnerabilidades nivel medio']/IssueListing/Chart/GroupingSection)");
			Integer numMedias = Integer.parseInt((String)expr.evaluate(doc, XPathConstants.STRING));
			Map<String,Integer> vunerabilidadesMedia = new HashMap<String, Integer>();
			expr = xpath.compile("//ReportDefinition/ReportSection[Title='Vulnerabilidades']/SubSection[Title='Tabla de vulnerabilidades nivel medio']/IssueListing/Chart/GroupingSection");
			listaVun = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			List<VulnerabilityResume> resumesMedium = new ArrayList<VulnerabilityResume>();
			for (int i=0;i<numMedias;i++) {
				Integer countVun = Integer.parseInt(listaVun.item(i).getAttributes().getNamedItem("count").getNodeValue());
				String nameVun = listaVun.item(i).getTextContent().trim();
				vunerabilidadesMedia.put(nameVun, countVun);
				VulnerabilityResume temp = new VulnerabilityResume();
				temp.setCount(countVun);
				temp.setLevel(Level.MEDIUM);
				temp.setName(nameVun);
				resumesMedium.add(temp);
			}
			//Nivel bajo
			expr = xpath.compile("count(//ReportDefinition/ReportSection[Title='Vulnerabilidades']/SubSection[Title='Tabla de vulnerabilidades nivel bajo']/IssueListing/Chart/GroupingSection)");
			Integer numBajas = Integer.parseInt((String)expr.evaluate(doc, XPathConstants.STRING));
			Map<String,Integer> vunerabilidadesBajas = new HashMap<String, Integer>();
			expr = xpath.compile("//ReportDefinition/ReportSection[Title='Vulnerabilidades']/SubSection[Title='Tabla de vulnerabilidades nivel bajo']/IssueListing/Chart/GroupingSection");
			listaVun = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			List<VulnerabilityResume> resumesLow = new ArrayList<VulnerabilityResume>();
			for (int i=0;i<numBajas;i++) {
				Integer countVun = Integer.parseInt(listaVun.item(i).getAttributes().getNamedItem("count").getNodeValue());
				String nameVun = listaVun.item(i).getTextContent().trim();
				vunerabilidadesBajas.put(nameVun, countVun);
				VulnerabilityResume temp = new VulnerabilityResume();
				temp.setCount(countVun);
				temp.setLevel(Level.LOW);
				temp.setName(nameVun);
				resumesLow.add(temp);
			}
			data.setVulnerabilitiesDetectedResume(new HashMap<Level, List<VulnerabilityResume>>());
			data.getVulnerabilitiesDetectedResume().put(Level.CRITIC, resumesCritic);
			data.getVulnerabilitiesDetectedResume().put(Level.HIGH, resumesHigh);
			data.getVulnerabilitiesDetectedResume().put(Level.MEDIUM, resumesMedium);
			data.getVulnerabilitiesDetectedResume().put(Level.LOW, resumesLow);
			
			////Resumen Tecnico
			doc = builder.parse(ClassLoader.getSystemResource("xml/RC_PALTA_VAR-17OCT2014_01_-_Informe_tecnico.xml").getFile());
			//Vunerabilidades detectadas
			//Nivel Critico
			List<VulnerabilityDetails> detailsCritic = new ArrayList<VulnerabilityDetails>();
			for (String vun : vunerabilidadesCriticas.keySet()) {
				VulnerabilityDetails temp = new VulnerabilityDetails();
				temp.setName(vun);
				temp.setLevel(Level.CRITIC);
				temp.setCount(vunerabilidadesCriticas.get(vun));
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']");
				Node vunera = (Node) expr.evaluate(doc, XPathConstants.NODE);
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Explanation']/Value");
				temp.setExplication(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Recommendations']/Value");
				temp.setRecomendation(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue");
				NodeList issues = (NodeList) expr.evaluate(doc,XPathConstants.NODESET);
				List<Issue> listIssue = new ArrayList<Issue>();
				for (int i = 1;i<=issues.getLength();i++) {
					Issue issueTemp = new Issue();
					Node issue = issues.item(i);
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Category");
					issueTemp.setCategory(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Folder");
					issueTemp.setFolder(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Friority");
					issueTemp.setFriority(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Kingdom");
					issueTemp.setKingdom(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Abstract");
					issueTemp.setAbstractI(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Tag[Name='Analysis']/Value");
					issueTemp.setAnalysis(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/FileName");
					issueTemp.setFile(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/LineStart");
					issueTemp.setLineStart(Integer.parseInt(((String) expr.evaluate(doc,XPathConstants.STRING)).trim()));
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/Snippet");
					issueTemp.setSnippet(((String) expr.evaluate(doc,XPathConstants.STRING)));
					listIssue.add(issueTemp);
				}
				temp.setListOfIssues(listIssue);
				detailsCritic.add(temp);
			}
			//Nivel alta
			List<VulnerabilityDetails> detailsHigh = new ArrayList<VulnerabilityDetails>();
			for (String vun : vunerabilidadesAltas.keySet()) {
				VulnerabilityDetails temp = new VulnerabilityDetails();
				temp.setName(vun);
				temp.setLevel(Level.HIGH);
				temp.setCount(vunerabilidadesAltas.get(vun));
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']");
				Node vunera = (Node) expr.evaluate(doc, XPathConstants.NODE);
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Explanation']/Value");
				temp.setExplication(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Recommendations']/Value");
				temp.setRecomendation(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue");
				NodeList issues = (NodeList) expr.evaluate(doc,XPathConstants.NODESET);
				List<Issue> listIssue = new ArrayList<Issue>();
				for (int i = 1;i<=issues.getLength();i++) {
					Issue issueTemp = new Issue();
					Node issue = issues.item(i);
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Category");
					issueTemp.setCategory(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Folder");
					issueTemp.setFolder(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Friority");
					issueTemp.setFriority(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Kingdom");
					issueTemp.setKingdom(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Abstract");
					issueTemp.setAbstractI(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Tag[Name='Analysis']/Value");
					issueTemp.setAnalysis(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/FileName");
					issueTemp.setFile(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/LineStart");
					issueTemp.setLineStart(Integer.parseInt(((String) expr.evaluate(doc,XPathConstants.STRING)).trim()));
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/Snippet");
					issueTemp.setSnippet(((String) expr.evaluate(doc,XPathConstants.STRING)));
					listIssue.add(issueTemp);
				}
				temp.setListOfIssues(listIssue);
				detailsHigh.add(temp);
			}
			//Nivel media
			List<VulnerabilityDetails> detailsMedium = new ArrayList<VulnerabilityDetails>();
			for (String vun : vunerabilidadesMedia.keySet()) {
				VulnerabilityDetails temp = new VulnerabilityDetails();
				temp.setName(vun);
				temp.setLevel(Level.MEDIUM);
				temp.setCount(vunerabilidadesMedia.get(vun));
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']");
				Node vunera = (Node) expr.evaluate(doc, XPathConstants.NODE);
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Explanation']/Value");
				temp.setExplication(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Recommendations']/Value");
				temp.setRecomendation(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue");
				NodeList issues = (NodeList) expr.evaluate(doc,XPathConstants.NODESET);
				List<Issue> listIssue = new ArrayList<Issue>();
				for (int i = 1;i<=issues.getLength();i++) {
					Issue issueTemp = new Issue();
					Node issue = issues.item(i);
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Category");
					issueTemp.setCategory(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Folder");
					issueTemp.setFolder(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Friority");
					issueTemp.setFriority(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Kingdom");
					issueTemp.setKingdom(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Abstract");
					issueTemp.setAbstractI(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Tag[Name='Analysis']/Value");
					issueTemp.setAnalysis(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/FileName");
					issueTemp.setFile(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/LineStart");
					issueTemp.setLineStart(Integer.parseInt(((String) expr.evaluate(doc,XPathConstants.STRING)).trim()));
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/Snippet");
					issueTemp.setSnippet(((String) expr.evaluate(doc,XPathConstants.STRING)));
					listIssue.add(issueTemp);
				}
				temp.setListOfIssues(listIssue);
				detailsMedium.add(temp);
			}
			//Nivel bajo
			List<VulnerabilityDetails> detailsLow = new ArrayList<VulnerabilityDetails>();
			for (String vun : vunerabilidadesBajas.keySet()) {
				VulnerabilityDetails temp = new VulnerabilityDetails();
				temp.setName(vun);
				temp.setLevel(Level.LOW);
				temp.setCount(vunerabilidadesBajas.get(vun));
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']");
				Node vunera = (Node) expr.evaluate(doc, XPathConstants.NODE);
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Explanation']/Value");
				temp.setExplication(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Recommendations']/Value");
				temp.setRecomendation(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue");
				NodeList issues = (NodeList) expr.evaluate(doc,XPathConstants.NODESET);
				List<Issue> listIssue = new ArrayList<Issue>();
				for (int i = 1;i<=issues.getLength();i++) {
					Issue issueTemp = new Issue();
					Node issue = issues.item(i);
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Category");
					issueTemp.setCategory(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Folder");
					issueTemp.setFolder(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Friority");
					issueTemp.setFriority(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Kingdom");
					issueTemp.setKingdom(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Abstract");
					issueTemp.setAbstractI(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Tag[Name='Analysis']/Value");
					issueTemp.setAnalysis(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/FileName");
					issueTemp.setFile(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/LineStart");
					issueTemp.setLineStart(Integer.parseInt(((String) expr.evaluate(doc,XPathConstants.STRING)).trim()));
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/Snippet");
					issueTemp.setSnippet(((String) expr.evaluate(doc,XPathConstants.STRING)));
					listIssue.add(issueTemp);
				}
				temp.setListOfIssues(listIssue);
				detailsLow.add(temp);
			}
			data.setVulnerabilitiesDetectedDetails(new HashMap<Level, List<VulnerabilityDetails>>());
			data.getVulnerabilitiesDetectedDetails().put(Level.CRITIC, detailsCritic);
			data.getVulnerabilitiesDetectedDetails().put(Level.HIGH, detailsHigh);
			data.getVulnerabilitiesDetectedDetails().put(Level.MEDIUM, detailsMedium);
			data.getVulnerabilitiesDetectedDetails().put(Level.LOW, detailsLow);
			
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (XPathExpressionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public FortifyReportData getData() {
		return data;
	}

	public void setData(FortifyReportData data) {
		this.data = data;
	}
	
	
}
