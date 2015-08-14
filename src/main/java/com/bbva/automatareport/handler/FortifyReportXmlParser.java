package com.bbva.automatareport.handler;

import java.io.IOException;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
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
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.bbva.automatareport.domain.FortifyReportData;
import com.bbva.automatareport.domain.Issue;
import com.bbva.automatareport.domain.Level;
import com.bbva.automatareport.domain.VulnerabilityDetails;
import com.bbva.automatareport.domain.VulnerabilityResume;

public class FortifyReportXmlParser extends DefaultHandler {
	private FortifyReportData data;
	private String path;
	
	public FortifyReportXmlParser(String path) {
		this.path = path;
		data = new FortifyReportData();
	}
	
	public void parser() {
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory
					.newInstance();
			DocumentBuilder builder;
			builder = factory.newDocumentBuilder();
			Document doc = builder.parse(path);
			XPathFactory xPathfactory = XPathFactory.newInstance();
			XPath xpath = xPathfactory.newXPath();
			//Numero ficheros
			XPathExpression expr = xpath.compile("/ReportDefinition/ReportSection[Title='Detailed Project Summary']/SubSection[Title='Numero Ficheros']/Text");
			String numFiles = (String)expr.evaluate(doc, XPathConstants.STRING);
			data.setNumFiles(NumberFormat.getNumberInstance(Locale.ITALY).format(Integer.valueOf(numFiles)));
			//Numero lineas
			expr = xpath.compile("/ReportDefinition/ReportSection[Title='Detailed Project Summary']/SubSection[Title='Lineas']/Text");
			String lineas = (String)expr.evaluate(doc, XPathConstants.STRING);
			data.setNumLines(NumberFormat.getNumberInstance(Locale.ITALY).format(Integer.valueOf(lineas)));
			//Lista de ficheros analizados
			expr = xpath.compile("/ReportDefinition/ReportSection[Title='Detailed Project Summary']/SubSection[Title='Lista Ficheros']/Text");
			String files = (String)expr.evaluate(doc, XPathConstants.STRING);
			Matcher m = Pattern.compile("(?m)^([a-zA-Z0-9_.-]*)?(\\/[a-zA-Z0-9_.-]+)+\\/?").matcher(files);
			data.setListOfFiles(new ArrayList<String>());
			while (m.find()) {
			   data.getListOfFiles().add(m.group());
			}
			////Resumen ejecutivo
			//Resumen de vulnerabilidades detectadas
			//Nivel critico
			expr = xpath.compile("count(//ReportDefinition/ReportSection[Title='1. Vulnerabilidades']/SubSection[Title='1.1 Vulnerabilidades de criticidad crítica']/IssueListing/Chart/GroupingSection)");
			Integer numCriticas = Integer.parseInt((String)expr.evaluate(doc, XPathConstants.STRING));
			Map<String,Integer> vunerabilidadesCriticas = new HashMap<String, Integer>();
			expr = xpath.compile("//ReportDefinition/ReportSection[Title='1. Vulnerabilidades']/SubSection[Title='1.1 Vulnerabilidades de criticidad crítica']/IssueListing/Chart/GroupingSection");
			NodeList listaVun = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			expr = xpath.compile("//ReportDefinition/ReportSection[Title='1. Vulnerabilidades']/SubSection[Title='1.1 Vulnerabilidades de criticidad crítica']/IssueListing/Chart/GroupingSection/groupTitle");
			NodeList listaVunName = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			List<VulnerabilityResume> resumesCritic = new ArrayList<VulnerabilityResume>();
			for (int i=0;i<numCriticas;i++) {
				Integer countVun = Integer.parseInt(listaVun.item(i).getAttributes().getNamedItem("count").getNodeValue());
				String nameVun = listaVunName.item(i).getTextContent().trim();
				vunerabilidadesCriticas.put(nameVun, countVun);
				VulnerabilityResume temp = new VulnerabilityResume();
				temp.setCount(countVun);
				temp.setLevel(Level.CRITIC);
				temp.setName(nameVun);
				resumesCritic.add(temp);
			}
			//Nivel alto
			expr = xpath.compile("count(//ReportDefinition/ReportSection[Title='1. Vulnerabilidades']/SubSection[Title='1.2 Vulnerabilidades de criticidad alta']/IssueListing/Chart/GroupingSection)");
			Integer numAltas = Integer.parseInt((String)expr.evaluate(doc, XPathConstants.STRING));
			Map<String,Integer> vunerabilidadesAltas = new HashMap<String, Integer>();
			expr = xpath.compile("//ReportDefinition/ReportSection[Title='1. Vulnerabilidades']/SubSection[Title='1.2 Vulnerabilidades de criticidad alta']/IssueListing/Chart/GroupingSection");			
			listaVun = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			expr = xpath.compile("//ReportDefinition/ReportSection[Title='1. Vulnerabilidades']/SubSection[Title='1.2 Vulnerabilidades de criticidad alta']/IssueListing/Chart/GroupingSection/groupTitle");
			listaVunName = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			List<VulnerabilityResume> resumesHigh = new ArrayList<VulnerabilityResume>();
			for (int i=0;i<numAltas;i++) {
				Integer countVun = Integer.parseInt(listaVun.item(i).getAttributes().getNamedItem("count").getNodeValue());
				String nameVun = listaVunName.item(i).getTextContent().trim();
				vunerabilidadesAltas.put(nameVun, countVun);
				VulnerabilityResume temp = new VulnerabilityResume();
				temp.setCount(countVun);
				temp.setLevel(Level.HIGH);
				temp.setName(nameVun);
				resumesHigh.add(temp);
			}
			//Nivel medio
			expr = xpath.compile("count(//ReportDefinition/ReportSection[Title='1. Vulnerabilidades']/SubSection[Title='1.3 Vulnerabilidades de criticidad media']/IssueListing/Chart/GroupingSection)");
			Integer numMedias = Integer.parseInt((String)expr.evaluate(doc, XPathConstants.STRING));
			Map<String,Integer> vunerabilidadesMedia = new HashMap<String, Integer>();
			expr = xpath.compile("//ReportDefinition/ReportSection[Title='1. Vulnerabilidades']/SubSection[Title='1.3 Vulnerabilidades de criticidad media']/IssueListing/Chart/GroupingSection");
			listaVun = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			expr = xpath.compile("//ReportDefinition/ReportSection[Title='1. Vulnerabilidades']/SubSection[Title='1.3 Vulnerabilidades de criticidad media']/IssueListing/Chart/GroupingSection/groupTitle");
			listaVunName = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			List<VulnerabilityResume> resumesMedium = new ArrayList<VulnerabilityResume>();
			for (int i=0;i<numMedias;i++) {
				Integer countVun = Integer.parseInt(listaVun.item(i).getAttributes().getNamedItem("count").getNodeValue());
				String nameVun = listaVunName.item(i).getTextContent().trim();
				vunerabilidadesMedia.put(nameVun, countVun);
				VulnerabilityResume temp = new VulnerabilityResume();
				temp.setCount(countVun);
				temp.setLevel(Level.MEDIUM);
				temp.setName(nameVun);
				resumesMedium.add(temp);
			}
			//Nivel bajo
			expr = xpath.compile("count(//ReportDefinition/ReportSection[Title='1. Vulnerabilidades']/SubSection[Title='1.4 Vulnerabilidades de criticidad baja']/IssueListing/Chart/GroupingSection)");
			Integer numBajas = Integer.parseInt((String)expr.evaluate(doc, XPathConstants.STRING));
			Map<String,Integer> vunerabilidadesBajas = new HashMap<String, Integer>();
			expr = xpath.compile("//ReportDefinition/ReportSection[Title='1. Vulnerabilidades']/SubSection[Title='1.4 Vulnerabilidades de criticidad baja']/IssueListing/Chart/GroupingSection");
			listaVun = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			expr = xpath.compile("//ReportDefinition/ReportSection[Title='1. Vulnerabilidades']/SubSection[Title='1.4 Vulnerabilidades de criticidad baja']/IssueListing/Chart/GroupingSection/groupTitle");
			listaVunName = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			List<VulnerabilityResume> resumesLow = new ArrayList<VulnerabilityResume>();
			for (int i=0;i<numBajas;i++) {
				Integer countVun = Integer.parseInt(listaVun.item(i).getAttributes().getNamedItem("count").getNodeValue());
				String nameVun = listaVunName.item(i).getTextContent().trim();
				vunerabilidadesBajas.put(nameVun, countVun);
				VulnerabilityResume temp = new VulnerabilityResume();
				temp.setCount(countVun);
				temp.setLevel(Level.LOW);
				temp.setName(nameVun);
				resumesLow.add(temp);
			}
			data.setVulnerabilitiesCriticDetectedResume(resumesCritic);
			data.setVulnerabilitiesHighDetectedResume(resumesHigh);
			data.setVulnerabilitiesMediumDetectedResume(resumesMedium);
			data.setVulnerabilitiesLowDetectedResume(resumesLow);
			
			//Vunerabilidades detectadas
			//Nivel Critico
			List<VulnerabilityDetails> detailsCritic = new ArrayList<VulnerabilityDetails>();
			for (String vun : vunerabilidadesCriticas.keySet()) {
				VulnerabilityDetails temp = new VulnerabilityDetails();
				temp.setName(vun);
				temp.setLevel(Level.CRITIC);
				temp.setCount(vunerabilidadesCriticas.get(vun));
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']");
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Explanation']/Value");
				temp.setExplication(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Recommendations']/Value");
				temp.setRecomendation(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue");
				NodeList issues = (NodeList) expr.evaluate(doc,XPathConstants.NODESET);
				List<Issue> listIssue = new ArrayList<Issue>();
				for (int i = 1;i<=issues.getLength();i++) {
					Issue issueTemp = new Issue();
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Category");
					issueTemp.setCategory(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Folder");
					issueTemp.setFolder(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Friority");
					issueTemp.setPriority(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Kingdom");
					issueTemp.setKingdom(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Abstract");
					issueTemp.setAbstractI(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Tag[Name='Analysis']/Value");
					issueTemp.setAnalysis(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/FileName");
					issueTemp.setFile(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/FilePath");
					issueTemp.setPath(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
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
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Explanation']/Value");
				temp.setExplication(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Recommendations']/Value");
				temp.setRecomendation(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue");
				NodeList issues = (NodeList) expr.evaluate(doc,XPathConstants.NODESET);
				List<Issue> listIssue = new ArrayList<Issue>();
				for (int i = 1;i<=issues.getLength();i++) {
					Issue issueTemp = new Issue();
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Category");
					issueTemp.setCategory(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Folder");
					issueTemp.setFolder(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Friority");
					issueTemp.setPriority(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Kingdom");
					issueTemp.setKingdom(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Abstract");
					issueTemp.setAbstractI(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Tag[Name='Analysis']/Value");
					issueTemp.setAnalysis(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/FileName");
					issueTemp.setFile(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/FilePath");
					issueTemp.setPath(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
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
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Explanation']/Value");
				temp.setExplication(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Recommendations']/Value");
				temp.setRecomendation(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue");
				NodeList issues = (NodeList) expr.evaluate(doc,XPathConstants.NODESET);
				List<Issue> listIssue = new ArrayList<Issue>();
				for (int i = 1;i<=issues.getLength();i++) {
					Issue issueTemp = new Issue();
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Category");
					issueTemp.setCategory(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Folder");
					issueTemp.setFolder(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Friority");
					issueTemp.setPriority(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Kingdom");
					issueTemp.setKingdom(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Abstract");
					issueTemp.setAbstractI(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Tag[Name='Analysis']/Value");
					issueTemp.setAnalysis(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/FileName");
					issueTemp.setFile(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/FilePath");
					issueTemp.setPath(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
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
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Explanation']/Value");
				temp.setExplication(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/MajorAttributeSummary/MetaInfo[Name='Recommendations']/Value");
				temp.setRecomendation(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
				expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue");
				NodeList issues = (NodeList) expr.evaluate(doc,XPathConstants.NODESET);
				List<Issue> listIssue = new ArrayList<Issue>();
				for (int i = 1;i<=issues.getLength();i++) {
					Issue issueTemp = new Issue();
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Category");
					issueTemp.setCategory(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Folder");
					issueTemp.setFolder(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Friority");
					issueTemp.setPriority(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Kingdom");
					issueTemp.setKingdom(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Abstract");
					issueTemp.setAbstractI(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Tag[Name='Analysis']/Value");
					issueTemp.setAnalysis(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/FileName");
					issueTemp.setFile(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/FilePath");
					issueTemp.setPath(((String) expr.evaluate(doc,XPathConstants.STRING)).trim());
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/LineStart");
					issueTemp.setLineStart(Integer.parseInt(((String) expr.evaluate(doc,XPathConstants.STRING)).trim()));
					expr = xpath.compile("//*/GroupingSection[groupTitle='" + vun + "']/Issue[" + i +"]/Primary/Snippet");
					issueTemp.setSnippet(((String) expr.evaluate(doc,XPathConstants.STRING)));
					listIssue.add(issueTemp);
				}
				temp.setListOfIssues(listIssue);
				detailsLow.add(temp);
			}
			data.setVulnerabilitiesCriticDetectedDetails(detailsCritic);
			data.setVulnerabilitiesHighDetectedDetails(detailsHigh);
			data.setVulnerabilitiesMediumDetectedDetails(detailsMedium);
			data.setVulnerabilitiesLowDetectedDetails(detailsLow);
			
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
