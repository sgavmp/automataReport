package com.bbva.automatareport;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.bbva.automatareport.domain.FortifyReportData;
import com.bbva.automatareport.handler.DataToWordWriter;
import com.bbva.automatareport.handler.FortifyReportXmlParser;

public class MainAutomataReport {

	public static void main(String[] args) {
		FortifyReportXmlParser parserFortify = new FortifyReportXmlParser();
		parserFortify.parser();
		FortifyReportData data = parserFortify.getData();
		//System.out.println(data);
		try {
			DataToWordWriter writerToWord = new DataToWordWriter(
					ClassLoader.getSystemResource("template.docx").getFile(), "./report.docx");
			writerToWord.makeWordReport(data);
			writerToWord.saveToFile();
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}

}
