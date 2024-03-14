import React, { useState, useEffect } from "react"

import Col from "react-bootstrap/Col"
import Row from "react-bootstrap/Row"

import Poi from "./Poi"

const PoiList = ({ pois, poi_categories, prefs, setPrefs }) => {

  const [selectedPois, setSelectedPois] = useState([])

  const refreshSelected = () => {
    let selected = []
    if (prefs.selectedCategoryIds.length > 0) {
      pois.forEach((poi) => {
        let cats = poi.poi_categories.map(e => e.id)
        for (let cat of cats) {
          for ( let s of prefs.selectedCategoryIds) {
            if (s === cat && !selected.some(p => p.id === poi.id)) selected.push(poi)
          }
        }
      })
    }
    else {
      selected = pois
    }
    setSelectedPois(selected)
  }

  useEffect(refreshSelected, [prefs.selectedCategoryIds, pois])

  return (
    <Row className="w-100">
      {
        selectedPois.map(poi => <Col
          key={poi.id}
          xs={{ span: 12 }}
          md={{ span: 4 }}
          xl={{ span: 6 }}
          className="d-flex justify-content-around align-items-center my-md-2"
        >
          <Poi
            poi={poi}
            setPrefs={setPrefs}
          >
          </Poi>
        </Col>)
      }
    </Row>
  )
}

export default PoiList
