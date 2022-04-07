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

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Token implements Serializable
{
    private String value;
    private boolean caseSensitive = false;
    
    public Token(String value, boolean caseSensitive)
    {
        this.value = value;
        this.caseSensitive = caseSensitive;
    }
    
    public String getValue()
    {
        return this.value;
    }
    
    public int getMatchType()
    {
        return 0;
    }
    
    public boolean getCaseSensitive()
    {
        return this.caseSensitive;
    }
    
    public boolean matches(String s)
    {
        if (this.caseSensitive)
        {
            return this.value.equals(s);
        }

        return this.value.equalsIgnoreCase(s);
    }
}
