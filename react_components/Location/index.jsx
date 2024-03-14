import React, { useReducer, useEffect, useState } from "react"
import FloorPlan from "react_components/shared/FloorPlan"
import { unifiedApiCall } from "shared/api"
import Row from "react-bootstrap/Row"
import Col from "react-bootstrap/Col"
import Form from 'react-bootstrap/Form';

import PoiList from "./PoiList"

const Location = ({ poi_categories, infrastructure_area_id, infrastructure_area_name, client_location, client_access_point, account_devices }) => {
  const reduceByMerge = (newState, oldState) => { return { ...newState, ...oldState } }
  const [poiCategories, setPoiCategories] = useState([])
  const [selectedDevice, setSelectedDevice] = useState(null)

  const apiDataInitialState = {
    latestLocations: [],
    placedAccessPoints: [],
    placedInfDevs: [],
    placedPois: [],
    placedPorts: [],
    placedSwitches: [],
    poiCategories: [],
    regions: [],
    unplacedAccessPoints: [],
    unplacedInfDevs: [],
    unplacedPois: [],
    unplacedPorts: [],
    unplacedSwitches: [],
    knownPois: []
  }
  const [apiData, setApiData] = useReducer(reduceByMerge, apiDataInitialState)

  // prefs -- Choices made by the user
  const prefsInitialState = {
    enableDrag: false,
    searchContext: false,
    searchMacs: [],
    searchString: "",
    showAps: false,
    showClients: true,
    showInfDevs: false,
    showManagePoiCategoriesModal: false,
    showPoiCategoryModal: false,
    showPoiModal: false,
    showPois: true,
    showRegions: false,
    showSwitchPorts: false,
    showSwitches: false,
    crowdingView: false,
    highlightedPois: [],
    selectedCategoryIds: []
  }
  const [prefs, setPrefs] = useReducer(reduceByMerge, prefsInitialState)

  const [accountDevices, setAccountDevices] = useState([])
  const [clientLocation, setClientLocation] = useState(null)

  const [selectedCategoryId, setSelectedCategoryId] = useState(0)

  useEffect(() => {
    if (selectedCategoryId === 0) {
      setApiData({
        placedPois: apiData.knownPois
      })
    } else {
      setApiData({
        placedPois: apiData.knownPois.filter(e => { return e.poi_categories.some(x => { return x.id === selectedCategoryId }) })
      })
    }
  }, [selectedCategoryId, apiData.knownPois])

  useEffect(() => {
    let _clientLocation = client_location ? JSON.parse(client_location) : null
    setClientLocation(_clientLocation)
    setApiData({ latestLocations: [_clientLocation].filter(e => e != null) })
    setPoiCategories(JSON.parse(poi_categories))
    setAccountDevices(
      JSON.parse(account_devices)
        .sort(accountDevice => accountDevice.mac === _clientLocation.mac ? -1 : 1)
    )
    if (typeof client_access_point !== 'undefined') { setApiData({ placedAccessPoints: [JSON.parse(client_access_point)] }) }
    let isMounted = true
    unifiedApiCall({
      collection: "pois",
      query: { infrastructure_area: infrastructure_area_id, ordering: "id" },
      success: ((data) => {
        if (isMounted) setApiData({ knownPois: data.data.results })
      })
    })
    return () => { isMounted = false }
  }, [])

  return (
    <div>
      <div className="d-flex flex-column flex-md-row justify-content-between mb-2">
        <h5 className="text-center text-md-left">{infrastructure_area_name}</h5>
        <div className="d-flex flex-column flex-md-row">
          <Form.Select
            aria-label="Select Poi Category"
            className="mx-md-2 mb-2 mb-md-0"
            defaultValue="0"
            onChange={(e) => { setSelectedCategoryId( parseInt(e.target.value)) }}
          >
            <option value="0">{__("Showing (All)")}</option>
            {poiCategories.map(poiCategory =>
              <option
                value={poiCategory.id}
                key={poiCategory.id}
              >
                {poiCategory.name}
              </option>
            )}
          </Form.Select>
        </div>
      </div>
      <Row>
        <Col xs={{ span: 12 }} xl={{ span: 8 }} className="d-flex justify-content-center pb-2">
          <FloorPlan
            floorId={infrastructure_area_id}
            prefs={prefs}
            apiData={apiData}
            setApiData={setApiData}
            accountView={true}
          />
        </Col>
        <Col xs={{ span: 12 }} xl={{ span: 4 }} className="d-flex justify-content-center">
          <PoiList
            pois={apiData.placedPois}
            poi_categories={apiData.poiCategories}
            prefs={prefs}
            setPrefs={setPrefs}
          />
        </Col>
      </Row>
    </div>
  )
}

export default Location
