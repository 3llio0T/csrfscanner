//    CSRF Scanner Extension for Burp Suite
//    Copyright (C) 2017  Adrian Hayter
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.

package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.DefaultListModel;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFormattedTextField;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.LayoutStyle;
import javax.swing.SwingUtilities;
import javax.swing.text.NumberFormatter;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JFrame parent;
    private JPanel panel;
    private JScrollPane scroll;
    
    private final Pattern FORM_OPEN_PATTERN = Pattern.compile("<form[^>]*>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL );
    private final Matcher FORM_OPEN_MATCHER = FORM_OPEN_PATTERN.matcher("");
    
    private final Pattern FORM_CLOSE_PATTERN = Pattern.compile("</form[^>]*>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private final Matcher FORM_CLOSE_MATCHER = FORM_CLOSE_PATTERN.matcher("");
    
    private final Color FONT_COLOR = new Color(0xE58925);
    
    // Issue Types
    private final String NO_TOKEN_IN_REQUEST_PARAMS = "Request vulnerable to Cross-site Request Forgery";
    private final String TOKEN_IN_REQUEST_PARAMS = "Anti-CSRF token detected in request";
    private final String SHORT_TOKEN = "Short Anti-CSRF token value detected";
    private final String NO_TOKEN_IN_RESPONSE_FORM = "Form does not contain an anti-CSRF token";
    private final String TOKEN_IN_RESPONSE_FORM = "Anti-CSRF token detected in form";
    
    // Defaults
    private final boolean DEFAULT_ONLY_SCAN_INSCOPE = true;
    private final boolean DEFAULT_REPORT_NO_PARAMS = false;
    private final String[] DEFAULT_METHOD_LIST = {"POST", "PUT", "DELETE", "PATCH"};
    private final boolean DEFAULT_GET_METHOD = false;
    private final boolean DEFAULT_POST_METHOD = true;
    private final boolean DEFAULT_PUT_METHOD = true;
    private final boolean DEFAULT_DELETE_METHOD = true;
    private final boolean DEFAULT_PATCH_METHOD = true;
    private ArrayList<Token> DEFAULT_TOKENS = new ArrayList<Token>();
    private final boolean DEFAULT_MIN_TOKEN = true;
    private final int DEFAULT_MIN_TOKEN_LENGTH = 16;
    private final boolean DEFAULT_NO_TOKEN_REQUESTS = true;
    private final boolean DEFAULT_NO_TOKEN_FORMS = true;
    private final boolean DEFAULT_FOUND_TOKEN_REQUESTS = false;
    private final boolean DEFAULT_FOUND_TOKEN_FORMS = false;
    
    // Settings
    private JCheckBox onlyScanInScope;
    private JCheckBox reportNoParams;
    private DefaultListModel<String> methods;
    private JCheckBox getMethod;
    private JCheckBox postMethod;
    private JCheckBox putMethod;
    private JCheckBox deleteMethod;
    private JCheckBox patchMethod;
    private JTable tokenTable;
    private TokenTableModel tokenTableModel;
    private JCheckBox tokenLengthCheck;
    private JFormattedTextField tokenLength;
    private int minTokenLength;
    private JCheckBox noTokenRequests;
    private JCheckBox noTokenForms;
    private JCheckBox foundTokenRequests;
    private JCheckBox foundTokenForms;
    
    @Override public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("CSRF Scanner");
        
        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
        
        // create our UI
        SwingUtilities.invokeLater(new Runnable() 
        {
            @Override
            public void run()
            {
                DEFAULT_TOKENS.add(new LiteralToken("token", false));
                DEFAULT_TOKENS.add(new RegexToken("(x|c)srf", false));
                DEFAULT_TOKENS.add(new RegexToken("(x|c)srf(-|_)?token", false));
                DEFAULT_TOKENS.add(new RegexToken("anti((x|c)srf|forgery)(token)?", false));
                DEFAULT_TOKENS.add(new RegexToken("(__)?RequestVerificationToken", false));
                DEFAULT_TOKENS.add(new LiteralToken("ViewStateUserKey", true));
                DEFAULT_TOKENS.add(new LiteralToken("forgery", false));
                DEFAULT_TOKENS.add(new LiteralToken("nonce", false));
                DEFAULT_TOKENS.add(new LiteralToken("csrfmiddlewaretoken", false));
                DEFAULT_TOKENS.add(new LiteralToken("_wpnonce", false));
                DEFAULT_TOKENS.add(new LiteralToken("_token", false));
                DEFAULT_TOKENS.add(new LiteralToken("_csrfToken", false));
                DEFAULT_TOKENS.add(new LiteralToken("_csrf", false));
                DEFAULT_TOKENS.add(new RegexToken("(X-)?XSRF-TOKEN", false));
                
                panel = new JPanel();
                scroll = new JScrollPane(panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                scroll.setBorder(BorderFactory.createEmptyBorder());
                
                parent = (JFrame) SwingUtilities.getRoot(scroll);
                
                JLabel title = new JLabel("Cross-site Request Forgery (CSRF) Scanner");
                title.setFont(new Font(title.getFont().getName(), Font.BOLD, 13));
                title.setForeground(FONT_COLOR);
                
                JLabel desc = new JLabel("Configure the list of recognised anti-CSRF tokens and other scanner settings.");
                
                JLabel csrfSettingsLabel = new JLabel("Scanner Settings");
                csrfSettingsLabel.setFont(new Font(csrfSettingsLabel.getFont().getName(), Font.PLAIN, 11));
                csrfSettingsLabel.setForeground(FONT_COLOR);
                
                onlyScanInScope = new JCheckBox("Only scan requests which are considered in-scope.");
                
                reportNoParams = new JCheckBox("Report requests that contain no parameters. This may cause an increase in false positives, but may be required when testing apps with REST-like URLs.");
                
                JLabel methodDesc = new JLabel("<html>Select the HTTP request methods to scan.</html>");
                methodDesc.putClientProperty("html.disable", null);
                methodDesc.setPreferredSize(new Dimension(panel.getWidth(), 100));
                
                methods = new DefaultListModel<String>();
                
                getMethod = new JCheckBox("GET");
                getMethod.addItemListener(new ItemListener()
                {
                    @Override public void itemStateChanged(ItemEvent e)
                    {
                        if (getMethod.isSelected())
                        {
                            if (!methods.contains("GET"))
                            {
                                methods.addElement("GET");
                            }
                        }
                        else
                        {
                            methods.removeElement("GET");
                        }
                    }
                });
                
                postMethod = new JCheckBox("POST");
                postMethod.addItemListener(new ItemListener()
                {
                    @Override public void itemStateChanged(ItemEvent e)
                    {
                        if (postMethod.isSelected())
                        {
                            if (!methods.contains("POST"))
                            {
                                methods.addElement("POST");
                            }
                        }
                        else
                        {
                            methods.removeElement("POST");
                        }
                    }
                });
                
                putMethod = new JCheckBox("PUT");
                putMethod.addItemListener(new ItemListener()
                {
                    @Override public void itemStateChanged(ItemEvent e)
                    {
                        if (putMethod.isSelected())
                        {
                            if (!methods.contains("PUT"))
                            {
                                methods.addElement("PUT");
                            }
                        }
                        else
                        {
                            methods.removeElement("PUT");
                        }
                    }
                });
                
                deleteMethod = new JCheckBox("DELETE");
                deleteMethod.addItemListener(new ItemListener()
                {
                    @Override public void itemStateChanged(ItemEvent e)
                    {
                        if (deleteMethod.isSelected())
                        {
                            if (!methods.contains("DELETE"))
                            {
                                methods.addElement("DELETE");
                            }
                        }
                        else
                        {
                            methods.removeElement("DELETE");
                        }
                    }
                });
                
                patchMethod = new JCheckBox("PATCH");
                patchMethod.addItemListener(new ItemListener()
                {
                    @Override public void itemStateChanged(ItemEvent e)
                    {
                        if (patchMethod.isSelected())
                        {
                            if (!methods.contains("PATCH"))
                            {
                                methods.addElement("PATCH");
                            }
                        }
                        else
                        {
                            methods.removeElement("PATCH");
                        }
                    }
                });
                
                JLabel csrfListLabel = new JLabel("Anti-CSRF Tokens");
                csrfListLabel.setFont(new Font(csrfListLabel.getFont().getName(), Font.PLAIN, 11));
                csrfListLabel.setForeground(FONT_COLOR);
                
                JButton addToken = new JButton("Add");
                addToken.addActionListener(new ActionListener()
                {
                    @Override public void actionPerformed(ActionEvent e)
                    {
                        JDialog addToken = new JDialog(parent, "Add Token", true);
                        JPanel addTokenPanel = new JPanel();

                        JLabel valueLabel = new JLabel("Value:");
                        JTextField value = new JTextField();
                        value.setMaximumSize(new Dimension(Integer.MAX_VALUE, value.getPreferredSize().height));
                        value.setMinimumSize(new Dimension(300, value.getPreferredSize().height));

                        JLabel matchTypeLabel = new JLabel("Match Type:");
                        ButtonGroup matchType = new ButtonGroup();
                        JRadioButton literal = new JRadioButton("Literal");
                        literal.setActionCommand("0");
                        JRadioButton regex = new JRadioButton("Regex");
                        regex.setActionCommand("1");
                        matchType.add(literal);
                        matchType.add(regex);
                        literal.setSelected(true);

                        JCheckBox caseSensitive = new JCheckBox("Case Sensitive");

                        JButton ok = new JButton("OK");
                        ok.addActionListener(new AddTokenActionListener(addToken, tokenTableModel, value, matchType, caseSensitive));

                        JButton cancel = new JButton("Cancel");
                        cancel.putClientProperty("parent", addToken);
                        cancel.addActionListener(new ActionListener()
                        {
                            @Override public void actionPerformed(ActionEvent e)
                            {
                                ((JDialog) (((JButton) e.getSource()).getClientProperty("parent"))).dispose();
                            }
                        });

                        GroupLayout layout = new GroupLayout(addTokenPanel);
                        addTokenPanel.setLayout(layout);
                        layout.setAutoCreateGaps(true);
                        layout.setAutoCreateContainerGaps(true);

                        layout.setHorizontalGroup(layout.createSequentialGroup()
                            .addGap(15)
                            .addGroup(layout.createParallelGroup()
                                .addGroup(layout.createSequentialGroup()
                                    .addComponent(valueLabel)
                                    .addComponent(value)
                                )
                                .addGroup(layout.createSequentialGroup()
                                    .addComponent(matchTypeLabel)
                                    .addComponent(literal)
                                    .addComponent(regex)
                                )
                                .addGroup(layout.createSequentialGroup()
                                    .addComponent(caseSensitive)
                                )
                                .addGroup(layout.createSequentialGroup()
                                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(ok)
                                    .addComponent(cancel)
                                )
                            )
                            .addGap(15)
                        );

                        layout.setVerticalGroup(layout.createSequentialGroup()
                            .addGap(15)
                            .addGroup(layout.createParallelGroup()
                                .addComponent(valueLabel, GroupLayout.Alignment.CENTER)
                                .addComponent(value, GroupLayout.Alignment.CENTER)
                            )
                            .addGap(10)
                            .addGroup(layout.createParallelGroup()
                                .addComponent(matchTypeLabel, GroupLayout.Alignment.CENTER)
                                .addComponent(literal, GroupLayout.Alignment.CENTER)
                                .addComponent(regex, GroupLayout.Alignment.CENTER)
                            )
                            .addGap(10)
                            .addGroup(layout.createParallelGroup()
                                .addComponent(caseSensitive)
                            )
                            .addGap(10)
                            .addGroup(layout.createParallelGroup()
                                .addComponent(ok)
                                .addComponent(cancel)
                            )
                            .addGap(15)
                        );

                        addToken.getContentPane().add(addTokenPanel);
                        addToken.pack();

                        addToken.setMinimumSize(new Dimension(addToken.getPreferredSize().width, addToken.getPreferredSize().height));

                        addToken.setLocationRelativeTo(parent);
                        addToken.setVisible(true);
                    }
                });
                
                JButton editToken = new JButton("Edit");
                editToken.addActionListener(new ActionListener()
                {
                    @Override public void actionPerformed(ActionEvent e)
                    {
                        int index = tokenTable.getSelectedRow();
                            
                        if (index != -1)
                        {
                            Token token = tokenTableModel.getToken(index);

                            JDialog editToken = new JDialog(parent, "Edit Token", true);
                            JPanel editTokenPanel = new JPanel();

                            JLabel valueLabel = new JLabel("Value:");
                            JTextField value = new JTextField();
                            value.setText(token.getValue());
                            value.setMaximumSize(new Dimension(Integer.MAX_VALUE, value.getPreferredSize().height));
                            value.setMinimumSize(new Dimension(300, value.getPreferredSize().height));

                            JLabel matchTypeLabel = new JLabel("Match Type:");
                            ButtonGroup matchType = new ButtonGroup();
                            JRadioButton literal = new JRadioButton("Literal");
                            literal.setActionCommand("0");
                            JRadioButton regex = new JRadioButton("Regex");
                            regex.setActionCommand("1");
                            matchType.add(literal);
                            matchType.add(regex);

                            if (token.getMatchType() == 1)
                            {
                                regex.setSelected(true);
                            }
                            else
                            {
                                literal.setSelected(true);
                            }

                            JCheckBox caseSensitive = new JCheckBox("Case Sensitive");
                            caseSensitive.setSelected(token.getCaseSensitive());

                            JButton ok = new JButton("OK");
                            ok.addActionListener(new EditTokenActionListener(editToken, tokenTableModel, index, value, matchType, caseSensitive));

                            JButton cancel = new JButton("Cancel");
                            cancel.putClientProperty("parent", editToken);
                            cancel.addActionListener(new ActionListener()
                            {
                                @Override public void actionPerformed(ActionEvent e)
                                {
                                    ((JDialog) (((JButton) e.getSource()).getClientProperty("parent"))).dispose();
                                }
                            });

                            GroupLayout layout = new GroupLayout(editTokenPanel);
                            editTokenPanel.setLayout(layout);
                            layout.setAutoCreateGaps(true);
                            layout.setAutoCreateContainerGaps(true);

                            layout.setHorizontalGroup(layout.createSequentialGroup()
                                .addGap(15)
                                .addGroup(layout.createParallelGroup()
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(valueLabel)
                                        .addComponent(value)
                                    )
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(matchTypeLabel)
                                        .addComponent(literal)
                                        .addComponent(regex)
                                    )
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(caseSensitive)
                                    )
                                    .addGroup(layout.createSequentialGroup()
                                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(ok)
                                        .addComponent(cancel)
                                    )
                                )
                                .addGap(15)
                            );

                            layout.setVerticalGroup(layout.createSequentialGroup()
                                .addGap(15)
                                .addGroup(layout.createParallelGroup()
                                    .addComponent(valueLabel, GroupLayout.Alignment.CENTER)
                                    .addComponent(value, GroupLayout.Alignment.CENTER)
                                )
                                .addGap(10)
                                .addGroup(layout.createParallelGroup()
                                    .addComponent(matchTypeLabel, GroupLayout.Alignment.CENTER)
                                    .addComponent(literal, GroupLayout.Alignment.CENTER)
                                    .addComponent(regex, GroupLayout.Alignment.CENTER)
                                )
                                .addGap(10)
                                .addGroup(layout.createParallelGroup()
                                    .addComponent(caseSensitive)
                                )
                                .addGap(10)
                                .addGroup(layout.createParallelGroup()
                                    .addComponent(ok)
                                    .addComponent(cancel)
                                )
                                .addGap(15)
                            );

                            editToken.getContentPane().add(editTokenPanel);
                            editToken.pack();

                            editToken.setMinimumSize(new Dimension(editToken.getPreferredSize().width, editToken.getPreferredSize().height));

                            editToken.setLocationRelativeTo(parent);
                            editToken.setVisible(true);
                        }
                    }
                });
                
                JButton removeToken = new JButton("Remove");
                removeToken.addActionListener(new ActionListener()
                {
                    @Override public void actionPerformed(ActionEvent e)
                    {
                        int[] rows = tokenTable.getSelectedRows();
                        Arrays.sort(rows);
                        
                        for (int i = rows.length - 1; i >= 0; i--)
                        {
                            int index = rows[i];
                            
                            tokenTableModel.remove(index);
                        }
                        tokenTableModel.getArray().trimToSize();
                        
                        tokenTableModel.fireTableDataChanged();
                    }
                });
                
                addToken.setMinimumSize(removeToken.getMinimumSize());
                editToken.setMinimumSize(removeToken.getMinimumSize());
                
                tokenTableModel = new TokenTableModel();
                tokenTable = new JTable(tokenTableModel);
                
                tokenTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
                
                JScrollPane tokenTableScrollPane = new JScrollPane(tokenTable);
                tokenTableScrollPane.setMaximumSize(new Dimension(900, 200));
                tokenTableScrollPane.setMinimumSize(new Dimension(900, 200));
                
                JLabel tokenAttributeLabel = new JLabel("Token Attribute Checks");
                tokenAttributeLabel.setFont(csrfListLabel.getFont());
                tokenAttributeLabel.setForeground(FONT_COLOR);
                
                tokenLengthCheck = new JCheckBox("Report instances when the anti-CSRF token value is less than");
                NumberFormat format = NumberFormat.getInstance();
                NumberFormatter formatter = new NumberFormatter(format);
                formatter.setValueClass(Integer.class);
                formatter.setMinimum(0);
                formatter.setMaximum(9999);
                formatter.setCommitsOnValidEdit(true);
                formatter.setAllowsInvalid(false);
                tokenLength = new JFormattedTextField(formatter);
                tokenLength.setValue(0);
                tokenLength.setColumns(4);
                tokenLength.addPropertyChangeListener("value", new PropertyChangeListener()
                {
                    @Override public void propertyChange(PropertyChangeEvent evt)
                    {
                        minTokenLength = Integer.parseInt(tokenLength.getText());
                    }
                });
                
                tokenLength.setMaximumSize(new Dimension(50, 20));
                JLabel tokenLengthEnd = new JLabel("characters in length.");
                
                JLabel missingTokenLabel = new JLabel("Missing Token Checks");
                missingTokenLabel.setFont(csrfListLabel.getFont());
                missingTokenLabel.setForeground(FONT_COLOR);
                
                JLabel noTokenDesc = new JLabel("<html>Anti-CSRF tokens are generally found in request parameters "
                        + "and in HTML forms contained within the response. It is recommended that both are scanned "
                        + "to ensure all vulnerable requests / forms are identified.</html>");
                noTokenDesc.putClientProperty("html.disable", null);
                noTokenDesc.setPreferredSize(new Dimension(panel.getWidth(), 100));
                JLabel noTokenLabel = new JLabel("Passively scan and report when anti-CSRF tokens are not detected in:");
                noTokenRequests = new JCheckBox("Request Parameters & Headers");
                noTokenForms = new JCheckBox("Response Forms");
                
                JLabel detectedTokenLabel = new JLabel("Detected Token Checks");
                detectedTokenLabel.setFont(csrfListLabel.getFont());
                detectedTokenLabel.setForeground(FONT_COLOR);
                JLabel foundTokenDesc = new JLabel("<html>Even if the application uses anti-CSRF tokens, they may not "
                + "have been implemented correctly or securely. For example, a request may still be successful "
                + "if the anti-CSRF token is modified or removed. It is important to perform manual tests on "
                + "these tokens for this reason, so knowing when they appear is also important. The following two "
                + "checks can help with this testing by reporting instances when anti-CSRF tokens appear.</html>");
                foundTokenDesc.putClientProperty("html.disable", null);
                foundTokenDesc.setPreferredSize(new Dimension(panel.getWidth(), 100));
                
                JLabel foundTokenLabel = new JLabel("Passively scan and report when anti-CSRF tokens are detected in:");
                
                foundTokenRequests = new JCheckBox("Request Parameters & Headers");
                foundTokenForms = new JCheckBox("Response Forms");
                
                JButton saveSettings = new JButton("Save Settings");
                saveSettings.addActionListener(new ActionListener()
                { 
                    @Override public void actionPerformed(ActionEvent e)
                    { 
                        saveConfig();
                    } 
                  });
                
                JButton restoreSettings = new JButton("Restore Saved Settings");
                restoreSettings.addActionListener(new ActionListener()
                { 
                    @Override public void actionPerformed(ActionEvent e)
                    { 
                        restoreConfig();
                    } 
                  });
                
                JButton restoreDefaults = new JButton("Restore Defaults");
                restoreDefaults.addActionListener(new ActionListener()
                { 
                    @Override public void actionPerformed(ActionEvent e)
                    { 
                        restoreDefaults();
                    } 
                  });
                
                GroupLayout layout = new GroupLayout(panel);
                panel.setLayout(layout);
                layout.setAutoCreateGaps(true);
                layout.setAutoCreateContainerGaps(true);
                
                layout.setHorizontalGroup(layout.createSequentialGroup()
                        .addGap(15)
                        .addGroup(layout.createParallelGroup()
                        .addComponent(title)
                        .addComponent(desc)
                        .addComponent(csrfSettingsLabel)
                        .addComponent(onlyScanInScope)
                        .addComponent(reportNoParams)
                        .addComponent(methodDesc)
                        .addGroup(layout.createSequentialGroup()
                        .addComponent(getMethod)
                        .addComponent(postMethod)
                        .addComponent(putMethod)
                        .addComponent(deleteMethod)
                        .addComponent(patchMethod))
                                
                        .addComponent(csrfListLabel)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(
                                layout.createParallelGroup()
                                .addComponent(addToken)
                                .addComponent(editToken)
                                .addComponent(removeToken)
                            )
                            .addComponent(tokenTableScrollPane)
                        )
                        
                        .addComponent(missingTokenLabel)
                        .addComponent(noTokenDesc)
                        .addComponent(noTokenLabel)
                        .addComponent(noTokenRequests)
                        .addComponent(noTokenForms)
                        .addComponent(detectedTokenLabel)
                        .addComponent(foundTokenDesc)
                        .addComponent(foundTokenLabel)
                        .addComponent(foundTokenRequests)
                        .addComponent(foundTokenForms)
                                
                        .addComponent(tokenAttributeLabel)
                        .addGroup(layout.createSequentialGroup()
                        .addComponent(tokenLengthCheck)
                        .addComponent(tokenLength)
                        .addComponent(tokenLengthEnd))
                                
                        .addGroup(layout.createSequentialGroup()
                        .addComponent(saveSettings)
                        .addComponent(restoreSettings)
                        .addComponent(restoreDefaults))));
                
                layout.setVerticalGroup(layout.createSequentialGroup()
                        .addGap(15)
                        .addComponent(title)
                        .addComponent(desc)
                        .addGap(15)
                                
                        .addComponent(csrfSettingsLabel)
                        .addComponent(onlyScanInScope)
                        .addComponent(reportNoParams)
                        .addGap(10)
                        .addComponent(methodDesc)
                        .addGroup(layout.createParallelGroup()
                        .addComponent(getMethod)
                        .addComponent(postMethod)
                        .addComponent(putMethod)
                        .addComponent(deleteMethod)
                        .addComponent(patchMethod))
                        .addGap(15)
                                
                        .addComponent(csrfListLabel)
                        .addGroup(layout.createParallelGroup()
                        .addComponent(tokenTableScrollPane)
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(addToken)
                            .addComponent(editToken)
                            .addComponent(removeToken)
                        )
                    )
                        .addGap(15)
                        
                        .addComponent(missingTokenLabel)
                        .addComponent(noTokenDesc)
                        .addGap(10)
                        .addComponent(noTokenLabel)
                        .addComponent(noTokenRequests)
                        .addComponent(noTokenForms)
                        .addGap(20)
                        .addComponent(detectedTokenLabel)
                        .addComponent(foundTokenDesc)
                        .addGap(10)
                        .addComponent(foundTokenLabel)
                        .addComponent(foundTokenRequests)
                        .addComponent(foundTokenForms)
                        .addGap(20)
                        .addComponent(tokenAttributeLabel)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(tokenLengthCheck)
                        .addComponent(tokenLength)
                        .addComponent(tokenLengthEnd))
                        .addGap(30)
                        .addGroup(layout.createParallelGroup()
                        .addComponent(saveSettings)
                        .addComponent(restoreSettings)
                        .addComponent(restoreDefaults)));
                
                restoreConfig();
                
                // customize our UI components
                callbacks.customizeUiComponent(scroll);
                
                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }
    
    public void saveConfig()
    {
        this.callbacks.saveExtensionSetting("save", "1");
        
        this.callbacks.saveExtensionSetting("onlyScanInScope", Boolean.toString(onlyScanInScope.isSelected()));
        
        this.callbacks.saveExtensionSetting("reportNoParams", Boolean.toString(reportNoParams.isSelected()));
        
        this.callbacks.saveExtensionSetting("getMethod", Boolean.toString(getMethod.isSelected()));
        this.callbacks.saveExtensionSetting("postMethod", Boolean.toString(postMethod.isSelected()));
        this.callbacks.saveExtensionSetting("putMethod", Boolean.toString(putMethod.isSelected()));
        this.callbacks.saveExtensionSetting("deleteMethod", Boolean.toString(deleteMethod.isSelected()));
        this.callbacks.saveExtensionSetting("patchMethod", Boolean.toString(patchMethod.isSelected()));
        
        this.callbacks.saveExtensionSetting("tokens", objectToString(tokenTableModel.getArray()));
        
        this.callbacks.saveExtensionSetting("tokenLengthCheck", Boolean.toString(tokenLengthCheck.isSelected()));
        this.callbacks.saveExtensionSetting("minTokenLength", Integer.toString(minTokenLength));
        
        this.callbacks.saveExtensionSetting("noTokenRequests", Boolean.toString(noTokenRequests.isSelected()));
        this.callbacks.saveExtensionSetting("noTokenForms", Boolean.toString(noTokenForms.isSelected()));
        
        this.callbacks.saveExtensionSetting("foundTokenRequests", Boolean.toString(foundTokenRequests.isSelected()));
        this.callbacks.saveExtensionSetting("foundTokenForms", Boolean.toString(foundTokenForms.isSelected()));
    }
    
    public void restoreConfig()
    {
        if (callbacks.loadExtensionSetting("save") == null || callbacks.loadExtensionSetting("save").equals("0"))
        {
            restoreDefaults();
        }
        else
        {
            if (this.callbacks.loadExtensionSetting("onlyScanInScope") != null)
            {
                onlyScanInScope.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("onlyScanInScope")));
            }
            else
            {
                onlyScanInScope.setSelected(DEFAULT_ONLY_SCAN_INSCOPE);
            }
            
            if (this.callbacks.loadExtensionSetting("reportNoParams") != null)
            {
                reportNoParams.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("reportNoParams")));
            }
            else
            {
                reportNoParams.setSelected(DEFAULT_REPORT_NO_PARAMS);
            }
            
            methods.removeAllElements();
            
            if (this.callbacks.loadExtensionSetting("getMethod") != null)
            {
                getMethod.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("getMethod")));
            }
            else
            {
                getMethod.setSelected(DEFAULT_GET_METHOD);
            }
            
            if (getMethod.isSelected())
            {
                if (!methods.contains("GET"))
                {
                    methods.addElement("GET");
                }
            }
            
            if (this.callbacks.loadExtensionSetting("postMethod") != null)
            {
                postMethod.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("postMethod")));
            }
            else
            {
                postMethod.setSelected(DEFAULT_POST_METHOD);
            }
            
            if (postMethod.isSelected())
            {
                if (!methods.contains("POST"))
                {
                    methods.addElement("POST");
                }
            }
            
            if (this.callbacks.loadExtensionSetting("putMethod") != null)
            {
                putMethod.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("putMethod")));
            }
            else
            {
                putMethod.setSelected(DEFAULT_PUT_METHOD);
            }
            
            if (putMethod.isSelected())
            {
                if (!methods.contains("PUT"))
                {
                    methods.addElement("PUT");
                }
            }
            
            if (this.callbacks.loadExtensionSetting("deleteMethod") != null)
            {
                deleteMethod.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("deleteMethod")));
            }
            else
            {
                deleteMethod.setSelected(DEFAULT_DELETE_METHOD);
            }
            
            if (deleteMethod.isSelected())
            {
                if (!methods.contains("DELETE"))
                {
                    methods.addElement("DELETE");
                }
            }
            
            if (this.callbacks.loadExtensionSetting("patchMethod") != null)
            {
                patchMethod.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("patchMethod")));
            }
            else
            {
                patchMethod.setSelected(DEFAULT_PATCH_METHOD);
            }
            
            if (patchMethod.isSelected())
            {
                if (!methods.contains("PATCH"))
                {
                    methods.addElement("PATCH");
                }
            }
            
            if (this.callbacks.loadExtensionSetting("tokens") != null)
            {
                try
                {
                    ArrayList<Token> tokens = new ArrayList<Token>();
                    
                    Object obj = stringToObject(this.callbacks.loadExtensionSetting("tokens"));
                    
                    if (obj instanceof DefaultListModel) // Convert from old list model to new table model.
                    {
                        DefaultListModel<String> oldTokens = (DefaultListModel<String>) obj;
                        
                        for (int i = 0; i < oldTokens.getSize(); i++)
                        {
                            tokens.add(new LiteralToken(oldTokens.elementAt(i), false));
                        }
                    }
                    else
                    {
                        tokens = (ArrayList<Token>) stringToObject(this.callbacks.loadExtensionSetting("tokens"));
                    }
                    
                    tokenTableModel.getArray().clear();
                    for (Token t : tokens)
                    {
                        tokenTableModel.getArray().add(t);
                    }
                }
                catch (Exception e)
                {
                    System.err.println(e.getMessage());
                    tokenTableModel.getArray().clear();
                    for (Token t : DEFAULT_TOKENS)
                    {
                        tokenTableModel.getArray().add(t);
                    }
                }
            }
            else
            {
                tokenTableModel.getArray().clear();
                for (Token t : DEFAULT_TOKENS)
                {
                    tokenTableModel.getArray().add(t);
                }
            }
            tokenTableModel.fireTableDataChanged();
            
            if (this.callbacks.loadExtensionSetting("tokenLengthCheck") != null)
            {
                tokenLengthCheck.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("tokenLengthCheck")));
            }
            else
            {
                tokenLengthCheck.setSelected(DEFAULT_MIN_TOKEN);
            }
            
            if (this.callbacks.loadExtensionSetting("minTokenLength") != null)
            {
                minTokenLength = Integer.parseInt(this.callbacks.loadExtensionSetting("minTokenLength"));
            }
            else
            {
                minTokenLength = DEFAULT_MIN_TOKEN_LENGTH;
            }
            tokenLength.setValue(minTokenLength);
            
            if (this.callbacks.loadExtensionSetting("noTokenRequests") != null)
            {
                noTokenRequests.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("noTokenRequests")));
            }
            else
            {
                noTokenRequests.setSelected(DEFAULT_NO_TOKEN_REQUESTS);
            }
            
            if (this.callbacks.loadExtensionSetting("noTokenForms") != null)
            {
                noTokenForms.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("noTokenForms")));
            }
            else
            {
                noTokenForms.setSelected(DEFAULT_NO_TOKEN_FORMS);
            }
            
            if (this.callbacks.loadExtensionSetting("foundTokenRequests") != null)
            {
                foundTokenRequests.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("foundTokenRequests")));
            }
            else
            {
                foundTokenRequests.setSelected(DEFAULT_FOUND_TOKEN_REQUESTS);
            }
            
            if (this.callbacks.loadExtensionSetting("foundTokenForms") != null)
            {
                foundTokenForms.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("foundTokenForms")));
            }
            else
            {
                foundTokenForms.setSelected(DEFAULT_FOUND_TOKEN_FORMS);
            }
        }
    }
    
    public void restoreDefaults()
    {
        this.callbacks.saveExtensionSetting("save", "2");
        
        onlyScanInScope.setSelected(DEFAULT_ONLY_SCAN_INSCOPE);
        
        reportNoParams.setSelected(DEFAULT_REPORT_NO_PARAMS);
        
        methods.removeAllElements();
        for (String s : DEFAULT_METHOD_LIST)
        {
            methods.addElement(s);
        }
        
        getMethod.setSelected(DEFAULT_GET_METHOD);
        postMethod.setSelected(DEFAULT_POST_METHOD);
        putMethod.setSelected(DEFAULT_PUT_METHOD);
        deleteMethod.setSelected(DEFAULT_DELETE_METHOD);
        patchMethod.setSelected(DEFAULT_PATCH_METHOD);
        
        tokenTableModel.getArray().clear();
        for (Token t : DEFAULT_TOKENS)
        {
            tokenTableModel.getArray().add(t);
        }
        tokenTableModel.fireTableDataChanged();
        
        tokenLengthCheck.setSelected(DEFAULT_MIN_TOKEN);
        tokenLength.setValue(DEFAULT_MIN_TOKEN_LENGTH);
        minTokenLength = DEFAULT_MIN_TOKEN_LENGTH;
        
        noTokenRequests.setSelected(DEFAULT_NO_TOKEN_REQUESTS);
        noTokenForms.setSelected(DEFAULT_NO_TOKEN_FORMS);
        
        foundTokenRequests.setSelected(DEFAULT_FOUND_TOKEN_REQUESTS);
        foundTokenForms.setSelected(DEFAULT_FOUND_TOKEN_FORMS);
    }
    
    public String objectToString(Object o)
    {
        try
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream out = new ObjectOutputStream(baos);
            out.writeObject(o);
            out.close();
            return this.helpers.base64Encode(baos.toByteArray());
        }
        catch (Exception e)
        {
            System.err.println(e.toString());
        }
        
        return "";
    }
    
    public Object stringToObject(String s)
    {
        try
        {
            byte [] data = this.helpers.base64Decode(s);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object o = ois.readObject();
            ois.close();
            return o;
        }
        catch (Exception e)
        {
            System.err.println(e.toString());
        }
        
        return new Object();
    }
    
    @Override public String getTabCaption()
    {
        return "CSRF";
    }

    @Override public Component getUiComponent()
    {
        return scroll;
    }

    @Override public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        if (!onlyScanInScope.isSelected() || callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl()))
        {
            List<IScanIssue> issues = new ArrayList<>();
            List<int[]> noTokenRequestHighlights = new ArrayList<>();
            List<int[]> noTokenFormsHighlights = new ArrayList<>();
            
            List<int[]> minRequestTokenLengthHighlights = new ArrayList<>();
            List<int[]> minResponseTokenLengthHighlights = new ArrayList<>();

            List<int[]> foundTokenRequestHighlights = new ArrayList<>();
            List<int[]> foundTokenFormsHighlights = new ArrayList<>();

            int requestOffset = helpers.analyzeResponse(baseRequestResponse.getRequest()).getBodyOffset();
            String requestBody = new String(baseRequestResponse.getRequest()).substring(requestOffset);

            int responseOffset = helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset();
            String responseBody = new String(baseRequestResponse.getResponse()).substring(responseOffset);

            int start = 0, end = 0, next = 0;
            boolean requestTokenFound = false;
            boolean token = false;
            String tokenValue = "";
            
            IRequestInfo request = helpers.analyzeRequest(baseRequestResponse);
            
            if (methods.contains(request.getMethod()))
            {
                List<IParameter> params = request.getParameters();
                
                // Remove invalid parameters (i.e. cookies)
                for (Iterator<IParameter> iterator = params.iterator(); iterator.hasNext();)
                {
                    IParameter param = iterator.next();
                    
                    if (param.getType() == IParameter.PARAM_COOKIE)
                    {
                        iterator.remove();
                    }
                }
                
                if (reportNoParams.isSelected() || !params.isEmpty())
                {
                    List<String> headers = request.getHeaders();
                    if (!headers.isEmpty())
                    {
                        boolean isRequestLine = true;
                        for (String header : headers)
                        {
                            if (isRequestLine) // Skip the first header.
                            {
                                isRequestLine = false;
                                continue;
                            }
                            
                            String[] headerArray = header.split(":", 2);

                            for (int i = 0; i < tokenTableModel.getRowCount(); i++)
                            {
                                if (tokenTableModel.getToken(i).matches(headerArray[0].trim()))
                                {
                                    token = true;
                                    requestTokenFound = true;
                                    if (headerArray.length == 2)
                                    {
                                        tokenValue = headerArray[1].trim();
                                    }
                                    else
                                    {
                                        tokenValue = "";
                                    }
                                    start = new String(baseRequestResponse.getRequest()).indexOf(header);
                                    end = start + header.length();
                                    break;
                                }
                            }
                            
                            if (token)
                            {
                                break;
                            }
                        }

                        if (token)
                        {
                            if (foundTokenRequests.isSelected())
                            {
                                foundTokenRequestHighlights.add(new int[] {start, end});
                            }

                            if (tokenLengthCheck.isSelected())
                            {    
                                try
                                {
                                    if (URLDecoder.decode(tokenValue, "UTF-8").length() < minTokenLength)
                                    {
                                        minRequestTokenLengthHighlights.add(new int[] {start, end});
                                    }
                                }
                                catch (UnsupportedEncodingException e){}
                            }
                        }
                    }

                    token = false;
                    start = 0;
                    end = 0;
                    next = 0;
                    
                    for (IParameter param : params)
                    {
                        if (param.getType() == IParameter.PARAM_BODY
                                || param.getType() == IParameter.PARAM_URL
                                || param.getType() == IParameter.PARAM_JSON
                                || param.getType() == IParameter.PARAM_MULTIPART_ATTR
                                || param.getType() == IParameter.PARAM_XML
                                || param.getType() == IParameter.PARAM_XML_ATTR) 
                        {
                            for (int i = 0; i < tokenTableModel.getRowCount(); i++)
                            {
                                if (tokenTableModel.getToken(i).matches(param.getName()))
                                {
                                    token = true;
                                    requestTokenFound = true;
                                    tokenValue = param.getValue();
                                    start = param.getNameStart();
                                    end = param.getValueEnd();
                                    break;
                                }
                            }
                            
                            if (token)
                            {
                                break;
                            }
                        }
                    }

                    if (token)
                    {
                        if (foundTokenRequests.isSelected())
                        {
                            foundTokenRequestHighlights.add(new int[] {start, end});
                        }

                        if (tokenLengthCheck.isSelected())
                        {    
                            try
                            {
                                if (URLDecoder.decode(tokenValue, "UTF-8").length() < minTokenLength)
                                {
                                    minRequestTokenLengthHighlights.add(new int[] {start, end});
                                }
                            }
                            catch (UnsupportedEncodingException e){}
                        }
                    }
                    
                    if (!requestTokenFound)
                    {
                        if (noTokenRequests.isSelected())
                        {
                            String query = helpers.analyzeRequest(baseRequestResponse).getUrl().getQuery();
                            if (query != null)
                            {
                                int queryStart = new String(baseRequestResponse.getRequest()).indexOf(query);
                                noTokenRequestHighlights.add(new int[] {queryStart, queryStart + query.length()});
                            }
                            noTokenRequestHighlights.add(new int[] {requestOffset, requestOffset + requestBody.length()});
                        }
                    }
                }
            }

            // Check Responses for Forms
            start = 0;
            end = 0;
            next = 0;
            
            FORM_OPEN_MATCHER.reset(responseBody);
            FORM_CLOSE_MATCHER.reset(responseBody);
            
            while (FORM_OPEN_MATCHER.find())
            {
                start = responseBody.indexOf(FORM_OPEN_MATCHER.group(), next);
                next = start;
                
                if (FORM_CLOSE_MATCHER.find())
                {
                    end = responseBody.indexOf(FORM_CLOSE_MATCHER.group(), next) + FORM_CLOSE_MATCHER.group().length();
                    next = end;
                    
                    Document doc = Jsoup.parse("<html><head></head><body>" + responseBody.substring(start, end) + "</body></html>");
                    token = false;
                    tokenValue = "";
                    Elements inputs = doc.select("input");
                    for (Element input : inputs)
                    {
                        if (input.hasAttr("name"))
                        {
                            for (int i = 0; i < tokenTableModel.getRowCount(); i++)
                            {
                                if (tokenTableModel.getToken(i).matches(input.attr("name")))
                                {
                                    token = true;
                                    tokenValue = input.val();
                                    break;
                                }
                            }
                            
                            if (token)
                            {
                                break;
                            }
                        }
                    }
                    
                    if (!token)
                    {
                        if (noTokenForms.isSelected())
                        {
                            noTokenFormsHighlights.add(new int[] {responseOffset + start, responseOffset + end});
                        }
                    }
                    else
                    {
                        if (foundTokenForms.isSelected())
                        {
                            foundTokenFormsHighlights.add(new int[] {responseOffset + start, responseOffset + end});
                        }

                        if (tokenLengthCheck.isSelected())
                        {
                            if (tokenValue.length() < minTokenLength)
                            {
                                minResponseTokenLengthHighlights.add(new int[] {responseOffset + start, responseOffset + end});
                            }
                        }
                    }
                }
            }

            if (!noTokenRequestHighlights.isEmpty())
            {                
                issues.add(new CSRFScanIssue(
                        NO_TOKEN_IN_REQUEST_PARAMS,
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, noTokenRequestHighlights, null)},
                        "High",
                        "Tentative",
                        "The request does not appear to contain an anti-CSRF token."
                    ));
            }
            
            if (!foundTokenRequestHighlights.isEmpty())
            {
                issues.add(new CSRFScanIssue(
                    TOKEN_IN_REQUEST_PARAMS,
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, foundTokenRequestHighlights, null)},
                    "Information",
                    "Firm",
                    "The request appears to contain an anti-CSRF token. It is suggested that the request "
                        + "be replayed both without and with a modified token to see if it is implemented properly."
                ));
            }
            
            if (!minRequestTokenLengthHighlights.isEmpty())
            {
                issues.add(new CSRFScanIssue(
                    SHORT_TOKEN,
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, minRequestTokenLengthHighlights, null)},
                    "Medium",
                    "Firm",
                    "The request appears to contain an anti-CSRF token with a value that is "
                        + "less than " + minTokenLength + " characters long. An attacker may be able to guess "
                        + "this token's value."
                ));
            }
            
            if (!minResponseTokenLengthHighlights.isEmpty())
            {
                String detail;
                if (minResponseTokenLengthHighlights.size() > 1)
                {
                    detail = "The response contains " + minResponseTokenLengthHighlights.size() + " forms which appear to "
                            + "contain an anti-CSRF token with a value that is less than " + minTokenLength
                            + " characters long. An attacker may be able to guess this token's value.";
                }
                else
                {
                    detail = "The response contains a form which appears to contain an anti-CSRF token with a "
                            + "value that is less than " + minTokenLength + " characters long. An attacker may "
                            + "be able to guess this token's value.";
                }
                
                issues.add(new CSRFScanIssue(
                    SHORT_TOKEN,
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, minResponseTokenLengthHighlights)},
                    "Medium",
                    "Firm",
                    detail
                ));
            }

            if (!noTokenFormsHighlights.isEmpty())
            {
                String detail = "";
                if (noTokenFormsHighlights.size() > 1)
                {
                    detail = "The response contains " + noTokenFormsHighlights.size() + " forms which do not appear to contain an anti-CSRF token.";
                }
                else
                {
                    detail = "The response contains a form which does not appear to contain an anti-CSRF token.";
                }

                issues.add(new CSRFScanIssue(
                    NO_TOKEN_IN_RESPONSE_FORM,
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, noTokenFormsHighlights)},
                    "High",
                    "Tentative",
                    detail
                ));
            }
            
            if (!foundTokenFormsHighlights.isEmpty())
            {
                String detail = "";
                if (foundTokenFormsHighlights.size() > 1)
                {
                    detail = "The response contains " + foundTokenFormsHighlights.size() + " forms which appear to "
                            + "contain an anti-CSRF token. It is suggested that the forms be submitted both without "
                            + "and with a modified token to see if it is implemented properly.";
                }
                else
                {
                    detail = "The response contains a form which appears to contain an anti-CSRF token. It is "
                            + "suggested that the form be submitted both without and with a modified token to "
                            + "see if it is implemented properly.";
                }

                issues.add(new CSRFScanIssue(
                    TOKEN_IN_RESPONSE_FORM,
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, foundTokenFormsHighlights)},
                    "Information",
                    "Firm",
                    detail
                ));
            }
            
            if (!issues.isEmpty())
            {
                return issues;
            }
        }
        
        return null;
    }

    @Override public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }

    @Override public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        final int DO_NOT_ADD_NEW_ISSUE = -1;
        final int ADD_NEW_ISSUE = 0;
        
        if (newIssue.getIssueName().equals(existingIssue.getIssueName()))
        {
            IRequestInfo newRequest = helpers.analyzeRequest(newIssue.getHttpMessages()[0]);
            IRequestInfo existingRequest = helpers.analyzeRequest(existingIssue.getHttpMessages()[0]);
            
            if (newRequest.getMethod().equals(existingRequest.getMethod()))
            {
                if (newRequest.getUrl().getPath().equals(existingRequest.getUrl().getPath()))
                {
                    List<IParameter> originalNewParams = newRequest.getParameters();
                    List<IParameter> originalExistingParams = existingRequest.getParameters();

                    // Rebuild parameter lists.
                    List<IParameter> newParams = new LinkedList<IParameter>();
                    for (IParameter param : originalNewParams)
                    {
                        if (param.getType() != IParameter.PARAM_COOKIE)
                        {
                            if (newIssue.getIssueName().equals(TOKEN_IN_REQUEST_PARAMS)) // Prevents duplicate tokens being reported.
                            {
                                boolean token = false;

                                for (int i = 0; i < tokenTableModel.getRowCount(); i++)
                                {
                                    if (tokenTableModel.getToken(i).matches(param.getName()))
                                    {
                                        token = true;
                                        break;
                                    }
                                }

                                if (!token)
                                {
                                    newParams.add(param);
                                }
                            }
                            else
                            {
                                newParams.add(param);
                            }
                        }
                    }

                    List<IParameter> existingParams = new LinkedList<IParameter>();
                    for (IParameter param : originalExistingParams)
                    {
                        if (param.getType() != IParameter.PARAM_COOKIE)
                        {
                            if (existingIssue.getIssueName().equals(TOKEN_IN_REQUEST_PARAMS)) // Prevents duplicate tokens being reported.
                            {
                                boolean token = false;

                                for (int i = 0; i < tokenTableModel.getRowCount(); i++)
                                {
                                    if (tokenTableModel.getToken(i).matches(param.getName()))
                                    {
                                        token = true;
                                        break;
                                    }
                                }

                                if (!token)
                                {
                                    existingParams.add(param);
                                }
                            }
                            else
                            {
                                existingParams.add(param);
                            }
                        }
                    }

                    if (newParams.size() == existingParams.size())
                    {
                        if (newParams.isEmpty())
                        {
                            return DO_NOT_ADD_NEW_ISSUE;
                        }
                        else
                        {
                            for (IParameter newParam : newParams)
                            {
                                boolean paramsMatch = false;

                                for (IParameter existingParam : existingParams)
                                {
                                    if (newParam.getType() == existingParam.getType() && newParam.getName().equals(existingParam.getName()) && newParam.getValue().equals(existingParam.getValue()))
                                    {
                                        paramsMatch = true;
                                        break;
                                    }
                                }

                                if (paramsMatch == false)
                                {
                                    return ADD_NEW_ISSUE;
                                }
                            }

                            return DO_NOT_ADD_NEW_ISSUE;
                        }
                    }
                    else
                    {
                        return ADD_NEW_ISSUE;
                    }
                }
                else // If the new issue has a different path to the existing issue, it should be added.
                {
                    return ADD_NEW_ISSUE;
                }
            }
            else // If the new issue has a different HTTP method to the existing issue, it should be added.
            {
                return ADD_NEW_ISSUE;
            }
        }
        else // If the new issue has a different name to the existing issue, it should be added.
        {
            return ADD_NEW_ISSUE;
        }
    }
}
    
class CSRFScanIssue implements IScanIssue
{
    private final String name, severity, confidence, detail;
    private final IHttpService httpService;
    private final URL url;
    private final IHttpRequestResponse[] httpMessages;

    public CSRFScanIssue(String name, IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String severity, String confidence, String detail)
    {
        this.name = name;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.severity = severity;
        this.confidence = confidence;
        this.detail = detail;
    }

    @Override public URL getUrl()
    {
        return url;
    }

    @Override public String getIssueName()
    {
        return name;
    }

    @Override public int getIssueType()
    {
        return 0;
    }

    @Override public String getSeverity()
    {
        return severity;
    }

    @Override public String getConfidence()
    {
        return confidence;
    }

    @Override public String getIssueBackground()
    {
        return "Cross-site Request Forgery (CSRF) is an attack which forces an end user to execute "
                + "unwanted actions on a web application to which he/she is currently authenticated. "
                + "With a little help of social engineering (like sending a link via email / chat), "
                + "an attacker may trick the users of a web application into executing actions of the "
                + "attacker's choosing. A successful CSRF exploit can compromise end user data and may "
                + "allow an attacker to perform an account hijack. If the targeted end user is the "
                + "administrator account, this can compromise the entire web application.";
    }

    @Override public String getRemediationBackground()
    {
        return "The application should implement anti-CSRF tokens into all requests that perform "
                + " actions which change the application state or which add/modify/delete content. "
                + "An anti-CSRF token should be a long randomly generated value unique to each user so "
                + "that attackers cannot easily brute-force it.<br><br>It is important that anti-CSRF tokens "
                + "are validated when user requests are handled by the application. The application should "
                + "both verify that the token exists in the request, and also check that it matches the user's current "
                + "token. If either of these checks fails, the application should reject the request.";
    }

    @Override public String getIssueDetail()
    {
        return detail;
    }

    @Override public String getRemediationDetail()
    {
        return null;
    }

    @Override public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override public IHttpService getHttpService()
    {
        return httpService;
    }
}

class AddTokenActionListener implements ActionListener
{
    private JDialog addToken;
    private TokenTableModel tokenTableModel;
    private JTextField value;
    private ButtonGroup matchType;
    private JCheckBox caseSensitive;

    public AddTokenActionListener(JDialog addToken, TokenTableModel tokenTableModel, JTextField value, ButtonGroup matchType, JCheckBox caseSensitive)
    {
        this.addToken = addToken;
        this.tokenTableModel = tokenTableModel;
        this.value = value;
        this.matchType = matchType;
        this.caseSensitive = caseSensitive;
    }

    @Override public void actionPerformed(ActionEvent e)
    {
        Token token = null;
        
        int matchTypeInt = Integer.parseInt(this.matchType.getSelection().getActionCommand());
        
        boolean errors = false;
        String errorText = "";
        
        if (value.getText().length() > 0)
        {
            if (matchTypeInt == 1)
            {
                try
                {
                    token = new RegexToken(value.getText(), caseSensitive.isSelected());
                }
                catch (PatternSyntaxException ex)
                {
                    errors = true;
                    errorText = "Invalid regular expression.";
                }
            }
            else
            {
                token = new LiteralToken(value.getText(), caseSensitive.isSelected());
            }
        }
        else
        {
            errors = true;
            errorText = "Please enter a value.";
        }

        if (errors)
        {
            JOptionPane.showMessageDialog(this.addToken, errorText, "Error", JOptionPane.ERROR_MESSAGE);
        }
        else
        {
            boolean tokenExists = false;
            for (Token r : tokenTableModel.getArray())
            {
                if (r.getValue().equals(token.getValue()) && r.getCaseSensitive() == token.getCaseSensitive() && r.getMatchType() == token.getMatchType())
                {
                    tokenExists = true;
                    break;
                }
            }

            if (tokenExists)
            {
                JOptionPane.showMessageDialog(this.addToken, "This token already exists.", "Error", JOptionPane.ERROR_MESSAGE);
            }
            else
            {
                this.tokenTableModel.add(token);
                this.tokenTableModel.fireTableDataChanged();
                this.addToken.dispose();
            }
        }
    }
}

class EditTokenActionListener implements ActionListener
{
    private JDialog editToken;
    private TokenTableModel tokenTableModel;
    private int index;
    private JTextField value;
    private ButtonGroup matchType;
    private JCheckBox caseSensitive;

    public EditTokenActionListener(JDialog editToken, TokenTableModel tokenTableModel, int index, JTextField value, ButtonGroup matchType, JCheckBox caseSensitive)
    {
        this.editToken = editToken;
        this.tokenTableModel = tokenTableModel;
        this.index = index;
        this.value = value;
        this.matchType = matchType;
        this.caseSensitive = caseSensitive;
    }

    @Override public void actionPerformed(ActionEvent e)
    {
        Token token = null;
        
        int matchTypeInt = Integer.parseInt(this.matchType.getSelection().getActionCommand());

        boolean errors = false;
        String errorText = "";
        
        if (value.getText().length() > 0)
        {
            if (matchTypeInt == 1)
            {
                try
                {
                    token = new RegexToken(value.getText(), caseSensitive.isSelected());
                }
                catch (PatternSyntaxException ex)
                {
                    errors = true;
                    errorText = "Invalid regular expression.";
                }
            }
            else
            {
                token = new LiteralToken(value.getText(), caseSensitive.isSelected());
            }
        }
        else
        {
            errors = true;
            errorText = "Please enter a value.";
        }
        
        if (errors)
        {
            JOptionPane.showMessageDialog(this.editToken, errorText, "Error", JOptionPane.ERROR_MESSAGE);
        }
        else
        {
            boolean tokenExists = false;
            for (Token r : tokenTableModel.getArray())
            {
                if (!r.equals(tokenTableModel.getToken(index)) && r.getValue().equals(token.getValue()) && r.getCaseSensitive() == token.getCaseSensitive() && r.getMatchType() == token.getMatchType())
                {
                    tokenExists = true;
                    break;
                }
            }

            if (tokenExists)
            {
                JOptionPane.showMessageDialog(this.editToken, "This token already exists.", "Error", JOptionPane.ERROR_MESSAGE);
            }
            else
            {
                this.tokenTableModel.update(this.index, token);
                this.tokenTableModel.fireTableDataChanged();
                this.editToken.dispose();
            }
        }
    }
}