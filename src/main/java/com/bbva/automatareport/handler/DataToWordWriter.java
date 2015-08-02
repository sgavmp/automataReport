package com.bbva.automatareport.handler;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import org.apache.commons.lang.StringUtils;
import org.docx4j.XmlUtils;
import org.docx4j.openpackaging.exceptions.Docx4JException;
import org.docx4j.openpackaging.packages.WordprocessingMLPackage;
import org.docx4j.wml.ContentAccessor;
import org.docx4j.wml.P;
import org.docx4j.wml.Tbl;
import org.docx4j.wml.Text;
import org.docx4j.wml.Tr;

import com.bbva.automatareport.domain.FortifyReportData;
import com.bbva.automatareport.domain.Level;

public class DataToWordWriter {

	private String file;
	private String fileToSave;
	private WordprocessingMLPackage wordFile;

	public DataToWordWriter(String filePathTemplate, String filePathReport)
			throws FileNotFoundException, Docx4JException {
		file = filePathTemplate;
		fileToSave = filePathReport;
		wordFile = getTemplate(filePathTemplate);
	}

	public void makeWordReport(FortifyReportData data) {
		replaceParagraph("$LIST_FILES", data.getListOfFiles(), wordFile, wordFile.getMainDocumentPart());
		replacePlaceholder(wordFile, data.getResumeScan(), "$RESUMEN_ESCANEO");
		replacePlaceholder(
				wordFile,
				String.valueOf(data.getVulnerabilitiesDetectedResume()
						.get(Level.CRITIC).size()), "$COUNT_CRITICAS");
		replacePlaceholder(
				wordFile,
				String.valueOf(data.getVulnerabilitiesDetectedResume()
						.get(Level.HIGH).size()), "$COUNT_ALTAS");
		replacePlaceholder(
				wordFile,
				String.valueOf(data.getVulnerabilitiesDetectedResume()
						.get(Level.MEDIUM).size()), "$COUNT_MEDIAS");
		replacePlaceholder(
				wordFile,
				String.valueOf(data.getVulnerabilitiesDetectedResume()
						.get(Level.LOW).size()), "$COUNT_BAJAS");

	}

	public void saveToFile() throws IOException, Docx4JException {
		writeDocxToStream(wordFile, fileToSave);
	}

	private WordprocessingMLPackage getTemplate(String name)
			throws Docx4JException, FileNotFoundException {
		WordprocessingMLPackage template = WordprocessingMLPackage
				.load(new FileInputStream(new File(name)));
		return template;
	}

	private static List<Object> getAllElementFromObject(Object obj,
			Class<?> toSearch) {
		List<Object> result = new ArrayList<Object>();
		if (obj instanceof JAXBElement)
			obj = ((JAXBElement<?>) obj).getValue();

		if (obj.getClass().equals(toSearch))
			result.add(obj);
		else if (obj instanceof ContentAccessor) {
			List<?> children = ((ContentAccessor) obj).getContent();
			for (Object child : children) {
				result.addAll(getAllElementFromObject(child, toSearch));
			}

		}
		return result;
	}

	private void replacePlaceholder(WordprocessingMLPackage template,
			String name, String placeholder) {
		List<Object> texts = getAllElementFromObject(
				template.getMainDocumentPart(), Text.class);

		for (Object text : texts) {
			Text textElement = (Text) text;
			if (textElement.getValue().equals(placeholder)) {
				textElement.setValue(name);
			}
		}
	}

	private void replaceParagraph(String placeholder, List<String> textToAdd,
			WordprocessingMLPackage template, ContentAccessor addTo) {
		// 1. get the paragraph
		List<Object> paragraphs = getAllElementFromObject(
				template.getMainDocumentPart(), P.class);

		P toReplace = null;
		for (Object p : paragraphs) {
			List<Object> texts = getAllElementFromObject(p, Text.class);
			for (Object t : texts) {
				Text content = (Text) t;
				if (content.getValue().equals(placeholder)) {
					toReplace = (P) p;
					content.setValue("");
					break;
				}
			}
		}

		for (String ptext : textToAdd) {

			// 3. copy the found paragraph to keep styling correct
			P copy = (P) XmlUtils.deepCopy(toReplace);

			// replace the text elements from the copy
			List<?> texts = getAllElementFromObject(copy, Text.class);
			if (texts.size() > 0) {
				Text textToReplace = (Text) texts.get(0);
				textToReplace.setValue(ptext);
			}

			// add the paragraph to the document
			toReplace.getContent().add(copy);
		}

	}

	private void replaceTable(String[] placeholders,
			List<Map<String, String>> textToAdd,
			WordprocessingMLPackage template) throws Docx4JException,
			JAXBException {
		List<Object> tables = getAllElementFromObject(
				template.getMainDocumentPart(), Tbl.class);

		// 1. find the table
		Tbl tempTable = getTemplateTable(tables, placeholders[0]);
		List<Object> rows = getAllElementFromObject(tempTable, Tr.class);

		// first row is header, second row is content
		if (rows.size() == 2) {
			// this is our template row
			Tr templateRow = (Tr) rows.get(1);

			for (Map<String, String> replacements : textToAdd) {
				// 2 and 3 are done in this method
				addRowToTable(tempTable, templateRow, replacements);
			}

			// 4. remove the template row
			tempTable.getContent().remove(templateRow);
		}

	}

	private Tbl getTemplateTable(List<Object> tables, String templateKey)
			throws Docx4JException, JAXBException {
		for (Iterator<Object> iterator = tables.iterator(); iterator.hasNext();) {
			Object tbl = iterator.next();
			List<?> textElements = getAllElementFromObject(tbl, Text.class);
			for (Object text : textElements) {
				Text textElement = (Text) text;
				if (textElement.getValue() != null
						&& textElement.getValue().equals(templateKey))
					return (Tbl) tbl;
			}
		}
		return null;
	}

	private static void addRowToTable(Tbl reviewtable, Tr templateRow,
			Map<String, String> replacements) {
		Tr workingRow = (Tr) XmlUtils.deepCopy(templateRow);
		List<?> textElements = getAllElementFromObject(workingRow, Text.class);
		for (Object object : textElements) {
			Text text = (Text) object;
			String replacementValue = (String) replacements
					.get(text.getValue());
			if (replacementValue != null)
				text.setValue(replacementValue);
		}

		reviewtable.getContent().add(workingRow);
	}

	private void writeDocxToStream(WordprocessingMLPackage template,
			String target) throws IOException, Docx4JException {
		File f = new File(target);
		template.save(f);
	}

}
