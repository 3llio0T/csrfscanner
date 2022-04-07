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

import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

public class TokenTableModel extends AbstractTableModel
{
    public final String[] matchTypes = {"Literal", "Regex"};
    
    private final String[] columnNames = {"Token Match", "Match Type", "Case Sensitive"};
    private ArrayList<Token> data = new ArrayList<Token>();
    
    @Override
    public int getRowCount()
    {
        return data.size();
    }

    @Override
    public int getColumnCount()
    {
        return columnNames.length;
    }
    
    @Override
    public String getColumnName(int col)
    {
        return columnNames[col];
    }
    
    @Override
    public Class getColumnClass(int col)
    {
        switch (col)
        {
            case 0:
                return String.class;
            case 1:
                return String.class;
            case 2:
                return Boolean.class;
            default:
                return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return data.get(rowIndex).getValue();
            case 1:
                return matchTypes[data.get(rowIndex).getMatchType()];
            case 2:
                return data.get(rowIndex).getCaseSensitive();
            default:
                return "";
        }
    }
    
    public ArrayList<Token> getArray()
    {
        return data;
    }
    
    public void setArray(ArrayList<Token> data)
    {
        this.data = data;
    }
    
    public Token getToken(int index)
    {
        return data.get(index);
    }
    
    public void add(Token token)
    {
        data.add(token);
    }
    
    public void update(int index, Token token)
    {
        data.set(index, token);
    }
    
    public void remove(int index)
    {
        data.remove(index);
    }
}
