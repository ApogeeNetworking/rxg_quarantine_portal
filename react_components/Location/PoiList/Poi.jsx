
import React, { useState, useEffect } from "react"
import Card from "react-bootstrap/Card"

import PoiIcon from "react_components/shared/PoiIcon"

const Poi = ({ poi, setPrefs }) => {
  const [highlighted, setHighlighted] = useState(false)
  const [classes, setClasses] = useState("w-100")
  const onMouseEnter = () => {
    setPrefs({ highlightedPois: [poi.id] })
    setHighlighted(true)
  }

  const onMouseLeave = () => {
    setPrefs({ highlightedPois: [] })
    setHighlighted(false)
  }

  useEffect(() => {
    if (highlighted) {
      setClasses("w-100 shadow")
    }
    else {
      setClasses("w-100")
    }
  }, [highlighted])
  return (
    <Card className={"w-100"}>
      <Card.Body
        onMouseEnter={onMouseEnter}
        onMouseLeave={onMouseLeave}
        className={classes}
      >
        <Card.Text className="d-flex align-items-center">
          <PoiIcon poi={poi} />&nbsp;&nbsp;<span>{poi.name}</span>
        </Card.Text>
      </Card.Body>
    </Card>
  )
}

export default Poi
