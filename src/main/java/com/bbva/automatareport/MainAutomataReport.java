package com.bbva.automatareport;

import java.awt.Color;
import java.awt.Font;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.util.Arrays;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PiePlot3D;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.ui.RectangleEdge;

import com.bbva.automatareport.domain.FortifyReportData;
import com.bbva.automatareport.handler.FortifyReportXmlParser;
import com.sun.star.beans.PropertyValue;
import com.sun.star.beans.XPropertySet;
import com.sun.star.comp.helper.BootstrapException;
import com.sun.star.container.XIndexAccess;
import com.sun.star.frame.XStorable;
import com.sun.star.lang.XComponent;
import com.sun.star.text.XDocumentIndex;
import com.sun.star.text.XDocumentIndexesSupplier;
import com.sun.star.uno.UnoRuntime;

import fr.opensagres.xdocreport.core.XDocReportException;
import fr.opensagres.xdocreport.document.IXDocReport;
import fr.opensagres.xdocreport.document.images.FileImageProvider;
import fr.opensagres.xdocreport.document.images.IImageProvider;
import fr.opensagres.xdocreport.document.registry.XDocReportRegistry;
import fr.opensagres.xdocreport.template.IContext;
import fr.opensagres.xdocreport.template.TemplateEngineKind;
import fr.opensagres.xdocreport.template.formatter.FieldsMetadata;

public class MainAutomataReport {

	public static void main(String[] args) throws XDocReportException, FileNotFoundException, IOException {
		Logger.getRootLogger().setLevel(Level.OFF);
		try {
			addLibraryPath("/usr/lib/libreoffice/program");
		} catch (Exception e1) {
			System.out.println("Es necesario tener instalado el SDK de LibreOffice en la ruta /usr/lib/libreoffice");
		}
		String templatePath = "";
		String reportDataPath = "";
		String applicationName = "";
		String applicationCode = "";
		if (args.length == 4) {
			templatePath = args[0];
			reportDataPath = args[1];
			applicationName = args[2];
			applicationCode = args[3];
		} else {
			System.out.println(
					"This command need 4 arguments.\nxmlToReport TEMPLATEPATH.odt REPORTPATHDATA.xml \"APPLICATIO NAME\" \"APPLICATION CODE\"");
			System.exit(0);
		}

		// 1) Load Docx file by filling Velocity template engine and cache
		// it to the registry
		InputStream in = new FileInputStream(templatePath);
		IXDocReport report = XDocReportRegistry.getRegistry().loadReport(in, TemplateEngineKind.Velocity);

		// 3) Create context Java model
		IContext context = report.createContext();

		FortifyReportXmlParser parserFortify = new FortifyReportXmlParser(reportDataPath);
		parserFortify.parser();
		FortifyReportData data = parserFortify.getData();
		data.setApplicationName(applicationName);
		data.setApplicationCode(applicationCode);
		// Prepare the data set
		DefaultPieDataset pieDataset = new DefaultPieDataset();
		data.calculateNumOfVulenrabilities();
		pieDataset.setValue("Criticas", data.getNumCritic());
		pieDataset.setValue("Altas", data.getNumHigh());
		pieDataset.setValue("Medias", data.getNumMedium());
		pieDataset.setValue("Bajas", data.getNumLow());

		// Create the chart
		JFreeChart chart2 = ChartFactory.createPieChart3D("Vulnerabilidades", pieDataset, true, false, false);
		PiePlot3D plot = (PiePlot3D) chart2.getPlot();
		plot.setLabelGenerator(null);
		plot.setBackgroundAlpha(0);
		chart2.setBackgroundPaint(Color.WHITE);
		chart2.getLegend().setPosition(RectangleEdge.TOP);
		chart2.getLegend().setItemFont(new Font("Arial", Font.PLAIN, 25));

		// Save chart as JPEG
		ChartUtilities.saveChartAsPNG(new File("chart.png"), chart2, 600, 400);
		FieldsMetadata metadata = new FieldsMetadata();
		metadata.addFieldAsImage("chart");
		report.setFieldsMetadata(metadata);
		context.put("report", data);
		IImageProvider chart = new FileImageProvider(new File("chart.png"), true);
		context.put("chart", chart);

		// 4) Generate report by merging Java model with the Docx
		OutputStream out = new FileOutputStream(new File("report_Out.odt"));
		report.process(context, out);
		in.close();
		out.close();

		com.sun.star.uno.XComponentContext xContext = null;

		// get the remote office component context
		try {
			xContext = com.sun.star.comp.helper.Bootstrap.bootstrap();
		} catch (BootstrapException e) {
			System.out.println("No es posible obtener la instancia de LibreOffice. Comprueba que esta instalado y es accesible.");
		}

		// get the remote office service manager
		com.sun.star.lang.XMultiComponentFactory xMCF = xContext.getServiceManager();

		Object oDesktop = null;
		try {
			oDesktop = xMCF.createInstanceWithContext("com.sun.star.frame.Desktop", xContext);
		} catch (Exception e) {
			System.out.println("No es posible abrir LibreOffice. Comprueba que esta instalado y es accesible.");
		}

		com.sun.star.frame.XComponentLoader xCompLoader = UnoRuntime
				.queryInterface(com.sun.star.frame.XComponentLoader.class, oDesktop);

		String sUrl = args[0];
		if (sUrl.indexOf("private:") != 0) {
			java.io.File sourceFile = new java.io.File("report_Out.odt");
			StringBuffer sbTmp = new StringBuffer("file:///");
			sbTmp.append(sourceFile.getCanonicalPath().replace('\\', '/'));
			sUrl = sbTmp.toString();
		}

		PropertyValue[] loadProps = new PropertyValue[2];

		loadProps[0] = new PropertyValue();
		loadProps[0].Name = "Hidden";
		loadProps[0].Value = Boolean.TRUE;

		loadProps[1] = new PropertyValue();
		loadProps[1].Name = "ReadOnly";
		loadProps[1].Value = Boolean.FALSE;

		// Load a Writer document, which will be automatically displayed
		com.sun.star.lang.XComponent xComp = null;
		try {
			xComp = xCompLoader.loadComponentFromURL(sUrl, "_default", 0, loadProps);
		} catch (com.sun.star.io.IOException e) {
			System.out.println("No es posible abrir el archivo " + sUrl);
		}

		try {
			updateDocumentIndexes(xComp);
		} catch (java.lang.Exception e) {
			System.out.println("Error al actualizar el indice del documento " + sUrl);
		}

		// save as a PDF
		XStorable xStorable = (XStorable) UnoRuntime.queryInterface(XStorable.class, xComp);

		PropertyValue[] propertyValues = new PropertyValue[3];
		propertyValues[0] = new PropertyValue();
		propertyValues[0].Name = "Overwrite";
		propertyValues[0].Value = new Boolean(true);
		propertyValues[1] = new PropertyValue();
		propertyValues[1].Name = "FilterName";
		propertyValues[1].Value = "writer_pdf_Export";
		propertyValues[0] = new PropertyValue();
		propertyValues[0].Name = "Hidden";
		propertyValues[0].Value = Boolean.TRUE;

		String oUrl = args[0];
		if (oUrl.indexOf("private:") != 0) {
			java.io.File sourceFile = new java.io.File("report.pdf");
			StringBuffer sbTmp = new StringBuffer("file:///");
			sbTmp.append(sourceFile.getCanonicalPath().replace('\\', '/'));
			oUrl = sbTmp.toString();
		}

		// Appending the favoured extension to the origin document name
		try {
			xStorable.storeToURL(oUrl, propertyValues);
		} catch (com.sun.star.io.IOException e) {
			System.out.println("Error al guardar el documento con la ruta " + oUrl);
		}
		xComp.dispose();

		System.out.println("Saved " + oUrl);
		System.exit(0);
	}

	/**
	 * Update all indexes in document
	 *
	 * @param xDoc
	 * @throws java.lang.Exception
	 */
	protected static void updateDocumentIndexes(XComponent xDoc) throws java.lang.Exception {

		// Get the DocumentIndexesSupplier interface of the document
		XDocumentIndexesSupplier xDocumentIndexesSupplier = (XDocumentIndexesSupplier) UnoRuntime
				.queryInterface(XDocumentIndexesSupplier.class, xDoc);

		// Get an XIndexAccess of DocumentIndexes
		XIndexAccess xDocumentIndexes = (XIndexAccess) UnoRuntime.queryInterface(XIndexAccess.class,
				xDocumentIndexesSupplier.getDocumentIndexes());

		int indexcount = xDocumentIndexes.getCount();

		for (int i = 0; i < indexcount; i++) {

			// Update each index
			XDocumentIndex xDocIndex = (XDocumentIndex) UnoRuntime.queryInterface(XDocumentIndex.class,
					xDocumentIndexes.getByIndex(i));

			// Get the service interface of the ContentIndex
			String indexType = xDocIndex.getServiceName();

			if (indexType.contains("com.sun.star.text.ContentIndex")) {

				XPropertySet xIndex = (XPropertySet) UnoRuntime.queryInterface(XPropertySet.class, xDocIndex);

				// Set TOC levels
				xIndex.setPropertyValue("Level", new Short((short) 4));
			}

			xDocIndex.update();
		}
	}
	
	/**
	* Adds the specified path to the java library path
	*
	* @param pathToAdd the path to add
	* @throws Exception
	 * @throws IllegalAccessException 
	 * @throws java.lang.IllegalArgumentException 
	 * @throws SecurityException 
	 * @throws NoSuchFieldException 
	*/
	public static void addLibraryPath(String pathToAdd) throws Exception, java.lang.IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException{
	    final Field usrPathsField = ClassLoader.class.getDeclaredField("usr_paths");
	    usrPathsField.setAccessible(true);

	    //get array of paths
	    final String[] paths = (String[])usrPathsField.get(null);

	    //check if the path to add is already present
	    for(String path : paths) {
	        if(path.equals(pathToAdd)) {
	            return;
	        }
	    }

	    //add the new path
	    final String[] newPaths = Arrays.copyOf(paths, paths.length + 1);
	    newPaths[newPaths.length-1] = pathToAdd;
	    usrPathsField.set(null, newPaths);
	}
}
