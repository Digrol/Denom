// Denom.org
// Author:  Evgeny Ksenofontov,  om1chcode@gmail.com

package org.denom.swing;

import java.util.*;
import java.util.List;
import java.awt.*;
import javax.swing.*;

import org.denom.format.JSONObject;

/**
 * Save/load Swing window location and panel location settings.
 */
public class SwingContainerParams
{
	// -----------------------------------------------------------------------------------------------------------------
	public static JSONObject toJSON( Container container )
	{
		JSONObject jo = new JSONObject();
		
		List<Component> components = new LinkedList<Component>();
		components.add( container );
		addChildComponents( container, components );

		int i = 0;
		for( Component component : components )
		{
			String compName = component.getClass().getCanonicalName() + i;
			JSONObject joComponent = Component_JSON( component );
			if( !joComponent.keySet().isEmpty() )
			{
				jo.put( compName, joComponent );
			}
			++i;
		}

		return jo;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void fromJSON( Container container, JSONObject json )
	{
		if( json == null )
		{
			return;
		}

		if( container instanceof JFrame )
		{	// Проверяем, попадает ли окно на один из доступных мониторов или нет
			JFrame f = new JFrame();
			String compName = container.getClass().getCanonicalName() + 0;
			loadComponentParams( json.optJSONObject( compName ), f );
			if( !intersectsScreen( f.getBounds() ) )
			{
				return;
			}
		}

		List<Component> components = new LinkedList<Component>();
		components.add( container );
		addChildComponents( container, components );

		int i = 0;
		for( Component component : components )
		{
			String compName = component.getClass().getCanonicalName() + i;
			loadComponentParams( json.optJSONObject( compName ), component );
			++i;
		}
	}

	//------------------------------------------------------------------------------------------------------------------
	// Получить список всех компонентов контейнера
	private static void addChildComponents( Container contaiter, List<Component> list )
	{
		for( Component comp : contaiter.getComponents() )
		{
			list.add( comp );
			if( comp instanceof Container )
			{
				addChildComponents( (Container)comp, list );
			}
		}
	}

	//------------------------------------------------------------------------------------------------------------------
	private static JSONObject Component_JSON( Component component )
	{
		JSONObject joComponent = new JSONObject();
		if( (component instanceof JFrame) )
		{
			int state = ((JFrame)component).getExtendedState();
			if( (state & Frame.ICONIFIED) != 0 )
			{
				state ^= Frame.ICONIFIED;
			}
			joComponent.put( "state", String.valueOf( state ) );
			((JFrame)component).setExtendedState( Frame.NORMAL );
		}
		
		if( (component instanceof JFrame) || (component instanceof JPanel) || (component instanceof JDialog) )
		{
			joComponent.put( "x", String.valueOf( component.getX() ) );
			joComponent.put( "y", String.valueOf( component.getY() ) );
			joComponent.put( "w", String.valueOf( component.getWidth() ) );
			joComponent.put( "h", String.valueOf( component.getHeight() ) );
		}

		if( component instanceof JSplitPane )
		{
			JSplitPane sp = (JSplitPane)component;
			joComponent.put( "div", String.valueOf( sp.getDividerLocation() ) );
		}
		
		return joComponent;
	}

	//------------------------------------------------------------------------------------------------------------------
	private static void loadComponentParams( JSONObject jo, Component component )
	{
		if( jo == null )
			return;
		
		if( (component instanceof JFrame) || (component instanceof JPanel) || (component instanceof JDialog) )
		{
			int x = jo.optInt( "x", component.getX() );
			int y = jo.optInt( "y", component.getY() );
			int w = jo.optInt( "w", component.getWidth() );
			int h = jo.optInt( "h", component.getHeight() );
			component.setBounds( x, y, w, h );
		}

		if( (component instanceof JFrame) )
		{
			int state = jo.optInt( "state", ((JFrame)component).getExtendedState() );
			((JFrame)component).setExtendedState( state );
		}

		if( component instanceof JSplitPane )
		{
			JSplitPane sp = (JSplitPane)component;
			sp.setDividerLocation( jo.optInt( "div", sp.getDividerLocation() ) );
		}
	}

	//------------------------------------------------------------------------------------------------------------------
	// Есть ли пересечение с каким-либо из работающих мониторов
	private static boolean intersectsScreen( Rectangle rect )
	{
		for( GraphicsDevice gd : GraphicsEnvironment.getLocalGraphicsEnvironment().getScreenDevices() )
		{
			for( GraphicsConfiguration gc : gd.getConfigurations() )
			{
				Rectangle bounds = gc.getBounds();
				if( rect.intersects( bounds ) )
				{
					return true;
				}
			}
		}
		return false;
	}

}
