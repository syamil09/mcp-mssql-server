USE [SAM_Prod]
GO
/****** Object:  StoredProcedure [dbo].[sp_generate_firestore_schema_store]    Script Date: 3/30/2026 1:52:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- Migration: Create stored procedure sp_generate_firestore_schema_store
-- Created:   2026-03-26 01:15:57
-- REWRITTEN: 2026-03-27 — all route types (FTO + MD + Survey)
-- Optimization: lean INSERT + batch UPDATEs for configs (avoids 35-JOIN bottleneck)

ALTER PROCEDURE [dbo].[sp_generate_firestore_schema_store]
(
    @CollectionName varchar(30),
    @ProcessDate    date
)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @szTestSalesId      varchar(50) = NULL;
    DECLARE @szTestCustId       varchar(50) = NULL;
    DECLARE @szTestWorkplaceId  varchar(50) = '0051';  -- e.g. '0051'

    DECLARE @TTL int, @ScopeType nvarchar(30), @ConfigCollectionName nvarchar(50);
    SELECT TOP 1 @ConfigCollectionName = CollectionName, @TTL = TTL, @ScopeType = ScopeType
    FROM SAM_Firestore_Config WHERE CollectionName = @CollectionName;

    -------------------------------------------------------------------
    -- STEP 1: Route discovery
    -------------------------------------------------------------------
    CREATE TABLE #routeCustomers (
        szSalesId varchar(50), szRouteId varchar(50), szCustId varchar(50)
    )

    INSERT INTO #routeCustomers
    SELECT f.szSalesId, f.szFTOId, x.szCustId
    FROM BOS_SD_FTO f WITH(NOLOCK)
    JOIN X_VW_SAM_SD_FTOItem x WITH(NOLOCK) ON x.szFTOId = f.szFTOId
    WHERE f.dtmFTO >= @ProcessDate AND f.dtmFTO < DATEADD(DAY, 1, @ProcessDate) AND f.bVoid = 0

    INSERT INTO #routeCustomers
    SELECT t.szEmployeeId, t.szDocId, ti.szCustomerId
    FROM SAM_SD_TWO t WITH(NOLOCK)
    JOIN SAM_SD_TWOItem ti WITH(NOLOCK) ON t.szDocId = ti.szDocId
    WHERE t.dtmDoc >= @ProcessDate AND t.dtmDoc < DATEADD(DAY, 1, @ProcessDate) AND t.bVoid = 0

    INSERT INTO #routeCustomers
    SELECT cl.szSalesId,
           CONCAT_WS('-', e.szWorkplaceId, cl.szSalesId, CONVERT(VARCHAR(8), @ProcessDate, 112)),
           cl.szDocId
    FROM SAM_AR_CustomerLead cl WITH(NOLOCK)
    JOIN BOS_PI_Employee e WITH(NOLOCK) ON e.szEmployeeId = cl.szSalesId
    WHERE cl.dtmVisit = @ProcessDate

    IF @szTestSalesId IS NOT NULL DELETE FROM #routeCustomers WHERE szSalesId != @szTestSalesId
    IF @szTestCustId IS NOT NULL  DELETE FROM #routeCustomers WHERE szCustId != @szTestCustId
    IF @szTestWorkplaceId IS NOT NULL
        DELETE rc FROM #routeCustomers rc
        WHERE NOT EXISTS (
            SELECT 1 FROM BOS_PI_Employee e WITH(NOLOCK)
            WHERE e.szEmployeeId = rc.szSalesId AND e.szWorkplaceId = @szTestWorkplaceId
        )

    CREATE INDEX IX_rc_sales ON #routeCustomers (szSalesId)
    CREATE INDEX IX_rc_cust  ON #routeCustomers (szCustId)
    CREATE INDEX IX_rc_route ON #routeCustomers (szRouteId)

    DECLARE @rcCount int; SELECT @rcCount = COUNT(*) FROM #routeCustomers;
    PRINT 'Step 1 done: #routeCustomers ' + CAST(@rcCount AS varchar(10))

    -------------------------------------------------------------------
    -- STEP 2a: Helper temp tables
    -------------------------------------------------------------------
    SELECT rc.szCustId, rc.szSalesId,
        CASE WHEN ch.szCustId IS NOT NULL THEN 1 ELSE 0 END AS bHasChillerTeam,
        ISNULL(SUM(ar.decCreditLimit), 0) AS decCreditLimitArClass,
        ISNULL(MAX(ar.szPaymentTermId), '') AS szPaymentTermIdArClass
    INTO #dataTOP
    FROM (SELECT DISTINCT szSalesId, szCustId FROM #routeCustomers WHERE LEFT(szRouteId, 2) != 'MD') rc
    JOIN BOS_PI_Employee e WITH(NOLOCK) ON e.szEmployeeId = rc.szSalesId
    LEFT JOIN BOS_PI_TeamArClass t WITH(NOLOCK) ON t.teamId = e.szTeamId
    LEFT JOIN BOS_AR_CustSalesArClass ar WITH(NOLOCK) ON ar.szArClassId = t.arClassId AND rc.szCustId = ar.szCustId
    LEFT JOIN (SELECT DISTINCT szCustId FROM SAM_ASM_Chiller WITH(NOLOCK) WHERE bActive = 1) ch ON ch.szCustId = rc.szCustId
    GROUP BY rc.szCustId, rc.szSalesId, ch.szCustId
    CREATE INDEX IX_dtop ON #dataTOP (szCustId, szSalesId)

    SELECT a.SzCustId, SUM(a.TotalSales) AS TotalSales
    INTO #dataHistory
    FROM StagingDB.dbo.Source_Sales3MonthbyCustomer a WITH(NOLOCK)
    WHERE a.SzCustId IN (SELECT szCustId FROM #routeCustomers)
    GROUP BY a.SzCustId
    CREATE INDEX IX_dh ON #dataHistory (SzCustId)

    PRINT 'Step 2a done: #dataTOP + #dataHistory'

    -------------------------------------------------------------------
    -- STEP 2b: CREATE TABLE #storeData
    -------------------------------------------------------------------
    CREATE TABLE #storeData (
        szSalesId nvarchar(50), szRouteId nvarchar(50), szCustId nvarchar(50),
        szWorkplaceId nvarchar(50), szTeamId nvarchar(50) DEFAULT '', szDepartmentId nvarchar(50) DEFAULT '',
        shItemNumber smallint DEFAULT 0, szBarcodeId nvarchar(50) DEFAULT '',
        szLatitude nvarchar(20) DEFAULT '', szLongitude nvarchar(20) DEFAULT '',
        szActivityStatusOrder nvarchar(5) DEFAULT '', szCustomerType nvarchar(10) DEFAULT '',
        szName nvarchar(255) DEFAULT '', CustszContactPerson nvarchar(250) DEFAULT '',
        CustszEmail nvarchar(250) DEFAULT '', szNoKTP nvarchar(50) DEFAULT '', szNPWP nvarchar(50) DEFAULT '',
        szRT nvarchar(5) DEFAULT '', szRW nvarchar(5) DEFAULT '', szNamaKTP nvarchar(250) DEFAULT '',
        TaxszAddress_1 nvarchar(250) DEFAULT '', TaxszAddress_2 nvarchar(250) DEFAULT '', TaxszDistrict nvarchar(250) DEFAULT '',
        CustszAddress_1 nvarchar(250) DEFAULT '', CustszAddress_2 nvarchar(250) DEFAULT '',
        CustszDistrict nvarchar(250) DEFAULT '', CustszCity nvarchar(250) DEFAULT '',
        CustszZipCode nvarchar(50) DEFAULT '', CustszState nvarchar(250) DEFAULT '', CustszCountry nvarchar(250) DEFAULT '',
        CustszMobileNo nvarchar(250) DEFAULT '', CustszPhoneNo_1 nvarchar(250) DEFAULT '', CustszPhoneNo_2 nvarchar(250) DEFAULT '',
        szDlvWorkplaceId nvarchar(50) DEFAULT '',
        szCategory_1 nvarchar(50) DEFAULT '', szCategory_2 nvarchar(50) DEFAULT '',
        szCategory_3 nvarchar(50) DEFAULT '', szCategory_4 nvarchar(50) DEFAULT '',
        szCategory_5 nvarchar(50) DEFAULT '', szCategory_6 nvarchar(50) DEFAULT '',
        szCategory_7 nvarchar(50) DEFAULT '', szCategory_8 nvarchar(50) DEFAULT '',
        szCategory_9 nvarchar(50) DEFAULT '', szCategory_10 nvarchar(50) DEFAULT '',
        szCategory_11 nvarchar(50) DEFAULT '', szCategory_12 nvarchar(50) DEFAULT '',
        szCategory_13 nvarchar(50) DEFAULT '', szCategory_14 nvarchar(50) DEFAULT '',
        szCategory_15 nvarchar(50) DEFAULT '',
        szCategory_1Desc nvarchar(100) DEFAULT '', szCategory_2Desc nvarchar(100) DEFAULT '',
        szCategory_3Desc nvarchar(100) DEFAULT '', szCategory_4Desc nvarchar(100) DEFAULT '',
        szCategory_5Desc nvarchar(100) DEFAULT '', szCategory_6Desc nvarchar(100) DEFAULT '',
        szCategory_7Desc nvarchar(100) DEFAULT '', szCategory_8Desc nvarchar(100) DEFAULT '',
        szCategory_9Desc nvarchar(100) DEFAULT '', szCategory_10Desc nvarchar(100) DEFAULT '',
        szCategory_11Desc nvarchar(100) DEFAULT '', szCategory_12Desc nvarchar(100) DEFAULT '',
        szCategory_13Desc nvarchar(100) DEFAULT '', szCategory_14Desc nvarchar(100) DEFAULT '',
        szCategory_15Desc nvarchar(100) DEFAULT '',
        decCreditLimit decimal(18,2) DEFAULT 0, decCreditLimitArClass decimal(18,2) DEFAULT 0,
        szPaymentTermId nvarchar(20) DEFAULT '', szPaymentTermIdArClass nvarchar(20) DEFAULT '',
        intPrintedMaxPaymentDay int DEFAULT 0,
        decMonthlyTarget decimal(18,2) DEFAULT 0, decPercentage decimal(18,2) DEFAULT 0,
        decTargetAmt decimal(18,2) DEFAULT 0, decTotalSalesPlan decimal(18,2) DEFAULT 0,
        decTargetRemain decimal(18,2) DEFAULT 0, decTargetDAP decimal(18,2) DEFAULT 0,
        decMonthlyActual decimal(18,2) DEFAULT 0, bEdited tinyint DEFAULT 0,
        decITGActual decimal(18,2) DEFAULT 0, decITGTarget decimal(18,2) DEFAULT 0,
        decMinOrderAmount nvarchar(50) DEFAULT '0', decMinimumOrderGTP nvarchar(50) DEFAULT '0',
        bAllowToCredit tinyint DEFAULT 0, bHasChillerTeam int DEFAULT 0,
        decMSSAchievement decimal(10,2) DEFAULT 0,
        szBarcodeCust nvarchar(50) DEFAULT '', szBarcodeCC nvarchar(50) DEFAULT '',
        szBarcodeSales nvarchar(50) DEFAULT '', szBarcodeWor nvarchar(50) DEFAULT '',
        szBarcodeDefault nvarchar(50) DEFAULT '',
        szFeatureAICust nvarchar(50) DEFAULT '', szFeatureAICC nvarchar(50) DEFAULT '',
        szFeatureAIDefault nvarchar(50) DEFAULT '',
        szManualProductAICust nvarchar(50) DEFAULT '', szManualProductAICC nvarchar(50) DEFAULT '',
        szManualProductAIDefault nvarchar(50) DEFAULT '',
        szGeofencingCust nvarchar(50) DEFAULT '', szGeofencingCC nvarchar(50) DEFAULT '',
        szGeofencingDefault nvarchar(50) DEFAULT '',
        szToggleAICust nvarchar(50) DEFAULT '', szToggleAICC nvarchar(50) DEFAULT '',
        szToggleAIDefault nvarchar(50) DEFAULT '',
        bDisableBarcode nvarchar(50) DEFAULT '0', bUpdateCoordinate tinyint DEFAULT 0,
        bIsCustomerMT nvarchar(50) DEFAULT '0',
        bShowPopupInformation nvarchar(50) DEFAULT '0', szMessagePopupInformation nvarchar(250) DEFAULT '',
        bAutoOrderWithStock nvarchar(50) DEFAULT '0',
        shOrderMissionMinOrder nvarchar(50) DEFAULT '0', bOrderMissionEnableSearch nvarchar(50) DEFAULT '0',
        bEnableOrderRangkul nvarchar(50) DEFAULT '0', bDisableOrderSAM nvarchar(50) DEFAULT '0',
        szCCPrevisit1Value nvarchar(100) DEFAULT '', szCCPrevisit2Value nvarchar(100) DEFAULT '',
        szConfigBarcode nvarchar(50) DEFAULT '', bRegisteredMsIdo bit DEFAULT 0,
        dtmDelivery varchar(10) DEFAULT '', dtmExpiredSO varchar(10) DEFAULT '',
        szTypeDeliveryPlan nvarchar(50) DEFAULT ''
    )

    -------------------------------------------------------------------
    -- STEP 2c: Branch 1 INSERT — FTO (lean: core data + targets only, NO config JOINs)
    -------------------------------------------------------------------
    INSERT INTO #storeData (
        szSalesId, szRouteId, szCustId, szWorkplaceId, szTeamId, szDepartmentId,
        shItemNumber, szBarcodeId, szLatitude, szLongitude, szActivityStatusOrder, szCustomerType,
        szName, CustszContactPerson, CustszEmail, szNoKTP, szNPWP,
        szRT, szRW, szNamaKTP, TaxszAddress_1, TaxszAddress_2, TaxszDistrict,
        CustszAddress_1, CustszAddress_2, CustszDistrict, CustszCity, CustszZipCode, CustszState, CustszCountry,
        CustszMobileNo, CustszPhoneNo_1, CustszPhoneNo_2, szDlvWorkplaceId,
        szCategory_1, szCategory_2, szCategory_3, szCategory_4, szCategory_5,
        szCategory_6, szCategory_7, szCategory_8, szCategory_9, szCategory_10,
        szCategory_11, szCategory_12, szCategory_13, szCategory_14, szCategory_15,
        szCategory_1Desc, szCategory_2Desc, szCategory_3Desc, szCategory_4Desc, szCategory_5Desc,
        szCategory_6Desc, szCategory_7Desc, szCategory_8Desc, szCategory_9Desc, szCategory_10Desc,
        szCategory_11Desc, szCategory_12Desc, szCategory_13Desc, szCategory_14Desc, szCategory_15Desc,
        decCreditLimit, szPaymentTermId, intPrintedMaxPaymentDay,
        decTargetAmt, decMonthlyTarget, decPercentage,
        decTotalSalesPlan, decTargetRemain, decTargetDAP, decMonthlyActual, bEdited,
        decITGActual, decITGTarget, decMinOrderAmount, bAllowToCredit, bUpdateCoordinate
    )
    SELECT
        rc.szSalesId, rc.szRouteId, x.szCustId, f.szWorkplaceId, e.szTeamId, e.szDepartmentId,
        x.shItemNumber, x.szBarcodeId, x.szLatitude, x.szLongitude, x.szActivityStatus, '',
        x.szName, x.CustszContactPerson, x.CustszEmail, x.szNoKTP, x.szNPWP,
        ISNULL(r.szRT, ''), ISNULL(r.szRW, ''), ISNULL(r.szNamaKTP, ''),
        ISNULL(inv.TaxszAddress_1, ''), ISNULL(inv.TaxszAddress_2, ''), ISNULL(inv.TaxszDistrict, ''),
        x.CustszAddress_1, x.CustszAddress_2, x.CustszDistrict, x.CustszCity, x.CustszZipCode, x.CustszState, x.CustszCountry,
        x.CustszMobileNo, x.CustszPhoneNo_1, x.CustszPhoneNo_2, x.szDlvWorkplaceId,
        x.szCategory_1, x.szCategory_2, x.szCategory_3, x.szCategory_4, x.szCategory_5,
        x.szCategory_6, x.szCategory_7, x.szCategory_8, x.szCategory_9, x.szCategory_10,
        x.szCategory_11, x.szCategory_12, x.szCategory_13, x.szCategory_14, x.szCategory_15,
        x.szCategory_1Desc, x.szCategory_2Desc, x.szCategory_3Desc, x.szCategory_4Desc, x.szCategory_5Desc,
        x.szCategory_6Desc, x.szCategory_7Desc, x.szCategory_8Desc, x.szCategory_9Desc, x.szCategory_10Desc,
        x.szCategory_11Desc, x.szCategory_12Desc, x.szCategory_13Desc, x.szCategory_14Desc, x.szCategory_15Desc,
        x.decCreditLimit, x.szPaymentTermId, x.intPrintedMaxPaymentDay,
        ISNULL(ct.decTargetAmt, 0),
        ISNULL(cm.decMonthlyTarget, 0),
        ISNULL((sm.TotalSales / NULLIF(cm.decMonthlyTarget, 0)) * 100, 0),
        ISNULL(di.decTotalSalesPlan, 0),
        CASE WHEN ISNULL(cm.decMonthlyTarget, 0) - ISNULL(sm.TotalSales, 0) < 0
             THEN 0 ELSE ISNULL(cm.decMonthlyTarget, 0) - ISNULL(sm.TotalSales, 0) END,
        ISNULL(di.decTotalSalesPlan, 0),
        ISNULL(sm.TotalSales, 0),
        ISNULL(di.bEdited, 0),
        ISNULL(itg.decITGActual, 0), ISNULL(itg.decITGTarget, 0),
        x.decMinOrderAmount, x.bAllowToCredit,
        ISNULL(cvg.bUpdateCoordinate, 0)
    FROM #routeCustomers rc
    JOIN X_VW_SAM_SD_FTOItem x WITH(NOLOCK) ON x.szFTOId = rc.szRouteId AND x.szCustId = rc.szCustId
    JOIN BOS_SD_FTO f WITH(NOLOCK) ON f.szFTOId = rc.szRouteId
    JOIN BOS_PI_Employee e WITH(NOLOCK) ON e.szEmployeeId = rc.szSalesId
    LEFT JOIN SNS_AddOn_CustRTRW r WITH(NOLOCK) ON x.szCustId = r.szCustId
    LEFT JOIN BOS_AR_CustInvoice inv WITH(NOLOCK) ON inv.szCustId = r.szCustId
    LEFT JOIN SAM_SD_CustomerSalesTargetToday ct WITH(NOLOCK) ON x.szCustId = ct.szCustId
    LEFT JOIN SAM_SD_CustomerMonthlyTarget cm WITH(NOLOCK) ON cm.szCustId = x.szCustId
    LEFT JOIN #dataHistory sm ON x.szCustId = sm.SzCustId
    LEFT JOIN sam_sd_dapItem di WITH(NOLOCK) ON e.szEmployeeId = di.szSalesId AND di.szCustId = x.szCustId
        AND di.dtmRouteDate >= @ProcessDate AND di.dtmRouteDate < DATEADD(DAY, 1, @ProcessDate)
    LEFT JOIN SAM_SD_ITGTarget itg WITH(NOLOCK) ON x.szCustId = itg.szCustId
    LEFT JOIN BOS_AR_CustomerVisitConfig cvg WITH(NOLOCK) ON x.szCustId = cvg.szCustId
    WHERE LEFT(rc.szRouteId, 2) != 'MD'
    OPTION (MAXDOP 8)

    PRINT 'Step 2c done: FTO INSERT ' + CAST(@@ROWCOUNT AS varchar(10))

    -------------------------------------------------------------------
    -- STEP 2d: Branch 1b INSERT — Survey routes
    -------------------------------------------------------------------
    INSERT INTO #storeData (
        szSalesId, szRouteId, szCustId, szWorkplaceId, szTeamId, szDepartmentId,
        szLatitude, szLongitude, szActivityStatusOrder, szCustomerType,
        szName, CustszContactPerson, CustszEmail,
        CustszAddress_1, CustszAddress_2,
        CustszMobileNo, CustszPhoneNo_1, CustszPhoneNo_2,
        szCategory_5Desc, szDlvWorkplaceId, szBarcodeDefault
    )
    SELECT
        rc.szSalesId, rc.szRouteId, cl.szDocId, cl.szWorkplaceId, e.szTeamId, e.szDepartmentId,
        cl.szLatitude, cl.szLongitude, 'ACT', 'survey',
        cl.szCustName, cl.szCustPhoneNumber, cl.szCustEmail,
        ISNULL(cl.szCustAddress, ''), ISNULL(cl.szCustAddress, ''),
        cl.szCustPhoneNumber, cl.szCustPhoneNumber, cl.szCustPhoneNumber,
        ISNULL(cl.szCustChannel, ''), cl.szWorkplaceId, 'G'
    FROM #routeCustomers rc
    JOIN SAM_AR_CustomerLead cl WITH(NOLOCK) ON cl.szDocId = rc.szCustId AND cl.szSalesId = rc.szSalesId AND cl.dtmVisit = @ProcessDate
    JOIN BOS_PI_Employee e WITH(NOLOCK) ON e.szEmployeeId = rc.szSalesId
    WHERE NOT EXISTS (SELECT 1 FROM BOS_SD_FTO WITH(NOLOCK) WHERE szFTOId = rc.szRouteId)
      AND LEFT(rc.szRouteId, 2) != 'MD'

    PRINT 'Step 2d done: Survey INSERT ' + CAST(@@ROWCOUNT AS varchar(10))

    -------------------------------------------------------------------
    -- STEP 2e: Branch 2 INSERT — MD routes (lean: core + category descs, no config JOINs)
    -------------------------------------------------------------------
    INSERT INTO #storeData (
        szSalesId, szRouteId, szCustId, szWorkplaceId,
        shItemNumber, szBarcodeId, szLatitude, szLongitude, szActivityStatusOrder,
        szName, CustszContactPerson, CustszEmail,
        CustszAddress_1, CustszAddress_2, CustszDistrict, CustszCity, CustszZipCode, CustszState, CustszCountry,
        CustszMobileNo, CustszPhoneNo_1, CustszPhoneNo_2, szDlvWorkplaceId,
        szCategory_1, szCategory_2, szCategory_3, szCategory_4, szCategory_5,
        szCategory_6, szCategory_7, szCategory_8, szCategory_9, szCategory_10,
        szCategory_11, szCategory_12, szCategory_13, szCategory_14, szCategory_15,
        szCategory_1Desc, szCategory_2Desc, szCategory_3Desc, szCategory_4Desc, szCategory_5Desc,
        szCategory_6Desc, szCategory_7Desc, szCategory_8Desc, szCategory_9Desc, szCategory_10Desc,
        szCategory_11Desc, szCategory_12Desc, szCategory_13Desc, szCategory_14Desc, szCategory_15Desc,
        szBarcodeCust, szBarcodeCC, szBarcodeSales, szBarcodeWor, szBarcodeDefault,
        szFeatureAICust, szFeatureAICC, szFeatureAIDefault,
        szManualProductAICust, szManualProductAICC, szManualProductAIDefault,
        bUpdateCoordinate
    )
    SELECT
        rc.szSalesId, rc.szRouteId, ti.szCustomerId, t.szWorkplaceId,
        ti.shItem, ISNULL(c.szBarcodeId, ''), ti.szLatitude, ti.szLongitude, 'NAC',
        c.szName, c.CustszContactPerson, c.CustszEmail,
        c.CustszAddress_1, c.CustszAddress_2, c.CustszDistrict, c.CustszCity, c.CustszZipCode, c.CustszState, c.CustszCountry,
        c.CustszMobileNo, c.CustszPhoneNo_1, c.CustszPhoneNo_2, c.szDlvWorkplaceId,
        ISNULL(c.szCategory_1, ''), ISNULL(c.szCategory_2, ''), ISNULL(c.szCategory_3, ''),
        ISNULL(c.szCategory_4, ''), ISNULL(c.szCategory_5, ''), ISNULL(c.szCategory_6, ''),
        ISNULL(c.szCategory_7, ''), ISNULL(c.szCategory_8, ''), ISNULL(c.szCategory_9, ''),
        ISNULL(c.szCategory_10, ''), ISNULL(c.szCategory_11, ''), ISNULL(c.szCategory_12, ''),
        ISNULL(c.szCategory_13, ''), ISNULL(c.szCategory_14, ''), ISNULL(c.szCategory_15, ''),
        ISNULL(Cat1.szDescription, ''), ISNULL(Cat2.szDescription, ''), ISNULL(Cat3.szDescription, ''),
        ISNULL(Cat4.szDescription, ''), ISNULL(Cat5.szDescription, ''), ISNULL(Cat6.szDescription, ''),
        ISNULL(Cat7.szDescription, ''), ISNULL(Cat8.szDescription, ''), ISNULL(Cat9.szDescription, ''),
        ISNULL(Cat10.szDescription, ''), ISNULL(Cat11.szDescription, ''), ISNULL(Cat12.szDescription, ''),
        ISNULL(Cat13.szDescription, ''), ISNULL(Cat14.szDescription, ''), ISNULL(Cat15.szDescription, ''),
        'S', 'S', 'S', 'S', 'S',
        '1', '1', '1',
        '1', '1', '1',
        ISNULL(cvg.bUpdateCoordinate, 0)
    FROM #routeCustomers rc
    JOIN SAM_SD_TWOItem ti WITH(NOLOCK) ON ti.szDocId = rc.szRouteId AND ti.szCustomerId = rc.szCustId
    JOIN SAM_SD_TWO t WITH(NOLOCK) ON t.szDocId = rc.szRouteId
    JOIN VW_SAM_CustomerMD c ON c.szCustId = ti.szCustomerId
    LEFT JOIN VW_SAM_AR_Category Cat1 WITH(NOLOCK) ON Cat1.szCategoryId = c.szCategory_1
    LEFT JOIN VW_SAM_AR_Category Cat2 WITH(NOLOCK) ON Cat2.szCategoryId = c.szCategory_2
    LEFT JOIN VW_SAM_AR_Category Cat3 WITH(NOLOCK) ON Cat3.szCategoryId = c.szCategory_3
    LEFT JOIN VW_SAM_AR_Category Cat4 WITH(NOLOCK) ON Cat4.szCategoryId = c.szCategory_4
    LEFT JOIN VW_SAM_AR_Category Cat5 WITH(NOLOCK) ON Cat5.szCategoryId = c.szCategory_5
    LEFT JOIN VW_SAM_AR_Category Cat6 WITH(NOLOCK) ON Cat6.szCategoryId = c.szCategory_6
    LEFT JOIN VW_SAM_AR_Category Cat7 WITH(NOLOCK) ON Cat7.szCategoryId = c.szCategory_7
    LEFT JOIN VW_SAM_AR_Category Cat8 WITH(NOLOCK) ON Cat8.szCategoryId = c.szCategory_8
    LEFT JOIN VW_SAM_AR_Category Cat9 WITH(NOLOCK) ON Cat9.szCategoryId = c.szCategory_9
    LEFT JOIN VW_SAM_AR_Category Cat10 WITH(NOLOCK) ON Cat10.szCategoryId = c.szCategory_10
    LEFT JOIN VW_SAM_AR_Category Cat11 WITH(NOLOCK) ON Cat11.szCategoryId = c.szCategory_11
    LEFT JOIN VW_SAM_AR_Category Cat12 WITH(NOLOCK) ON Cat12.szCategoryId = c.szCategory_12
    LEFT JOIN VW_SAM_AR_Category Cat13 WITH(NOLOCK) ON Cat13.szCategoryId = c.szCategory_13
    LEFT JOIN VW_SAM_AR_Category Cat14 WITH(NOLOCK) ON Cat14.szCategoryId = c.szCategory_14
    LEFT JOIN VW_SAM_AR_Category Cat15 WITH(NOLOCK) ON Cat15.szCategoryId = c.szCategory_15
    LEFT JOIN BOS_AR_CustomerVisitConfig cvg WITH(NOLOCK) ON ti.szCustomerId = cvg.szCustId
    WHERE LEFT(rc.szRouteId, 2) = 'MD'

    PRINT 'Step 2e done: MD INSERT ' + CAST(@@ROWCOUNT AS varchar(10))

    CREATE INDEX IX_sd_cust   ON #storeData (szCustId)
    CREATE INDEX IX_sd_sales  ON #storeData (szSalesId)
    CREATE INDEX IX_sd_cat1   ON #storeData (szCategory_1)
    CREATE INDEX IX_sd_cat6   ON #storeData (szCategory_6)

    -------------------------------------------------------------------
    -- STEP 2f: Config UPDATEs — one per config template (fast indexed lookups)
    -- Each UPDATE hits SAM_SM_ConfigInfoItem once instead of 35x in a single JOIN
    -------------------------------------------------------------------

    -- Barcode: CUS level
    UPDATE sd SET sd.szBarcodeCust = ci.szValue
    FROM #storeData sd
    JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.barcode' AND ci.szConfigItemTypeId = 'CUS' AND ci.szConfigItemTypeValue = sd.szCustId
    WHERE sd.szCustomerType != 'survey' AND LEFT(sd.szRouteId, 2) != 'MD'

    -- Barcode: CC level
    UPDATE sd SET sd.szBarcodeCC = ci.szValue
    FROM #storeData sd
    JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.barcode' AND ci.szConfigItemTypeId = 'CC' AND ci.szConfigItemTypeValue = sd.szCategory_1
    WHERE sd.szCustomerType != 'survey' AND LEFT(sd.szRouteId, 2) != 'MD'

    -- Barcode: SLS level
    UPDATE sd SET sd.szBarcodeSales = ci.szValue
    FROM #storeData sd
    JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.barcode' AND ci.szConfigItemTypeId = 'SLS' AND ci.szConfigItemTypeValue = sd.szSalesId
    WHERE sd.szCustomerType != 'survey' AND LEFT(sd.szRouteId, 2) != 'MD'

    -- Barcode: WOR level
    UPDATE sd SET sd.szBarcodeWor = ci.szValue
    FROM #storeData sd
    JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.barcode' AND ci.szConfigItemTypeId = 'WOR' AND ci.szConfigItemTypeValue = sd.szWorkplaceId
    WHERE sd.szCustomerType != 'survey' AND LEFT(sd.szRouteId, 2) != 'MD'

    -- Barcode: Default
    UPDATE sd SET sd.szBarcodeDefault = ct.szDefaultValue
    FROM #storeData sd
    CROSS JOIN SAM_SM_ConfigTemplateItem ct WITH(NOLOCK)
    WHERE ct.szConfigTemplateId = 'com.sam.barcode' AND ct.szConfigItemTypeId = 'CUS'
      AND sd.szCustomerType != 'survey' AND LEFT(sd.szRouteId, 2) != 'MD'

    PRINT 'Step 2f: barcode configs done'

    -- FeatureAI: CUS, CC, Default
    UPDATE sd SET sd.szFeatureAICust = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.enablefeatureai' AND ci.szConfigItemTypeId = 'CUS' AND ci.szConfigItemTypeValue = sd.szCustId
    WHERE LEFT(sd.szRouteId, 2) != 'MD'

    UPDATE sd SET sd.szFeatureAICC = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.enablefeatureai' AND ci.szConfigItemTypeId = 'CC' AND ci.szConfigItemTypeValue = sd.szCategory_1
    WHERE LEFT(sd.szRouteId, 2) != 'MD'

    UPDATE sd SET sd.szFeatureAIDefault = ct.szDefaultValue
    FROM #storeData sd CROSS JOIN SAM_SM_ConfigTemplateItem ct WITH(NOLOCK)
    WHERE ct.szConfigTemplateId = 'com.sam.enablefeatureai' AND ct.szConfigItemTypeId = 'CUS' AND LEFT(sd.szRouteId, 2) != 'MD'

    -- ManualProductAI: CUS, CC, Default
    UPDATE sd SET sd.szManualProductAICust = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.enablemanualaddproductdisplaymt' AND ci.szConfigItemTypeId = 'CUS' AND ci.szConfigItemTypeValue = sd.szCustId
    WHERE LEFT(sd.szRouteId, 2) != 'MD'

    UPDATE sd SET sd.szManualProductAICC = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.enablemanualaddproductdisplaymt' AND ci.szConfigItemTypeId = 'CC' AND ci.szConfigItemTypeValue = sd.szCategory_1
    WHERE LEFT(sd.szRouteId, 2) != 'MD'

    UPDATE sd SET sd.szManualProductAIDefault = ct.szDefaultValue
    FROM #storeData sd CROSS JOIN SAM_SM_ConfigTemplateItem ct WITH(NOLOCK)
    WHERE ct.szConfigTemplateId = 'com.sam.enablemanualaddproductdisplaymt' AND ct.szConfigItemTypeId = 'CUS' AND LEFT(sd.szRouteId, 2) != 'MD'

    -- Geofencing: CUS, CC, Default (both FTO and MD)
    UPDATE sd SET sd.szGeofencingCust = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.geofencing' AND ci.szConfigItemTypeId = 'CUS' AND ci.szConfigItemTypeValue = sd.szCustId

    UPDATE sd SET sd.szGeofencingCC = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.geofencing' AND ci.szConfigItemTypeId = 'CC' AND ci.szConfigItemTypeValue = sd.szCategory_1

    UPDATE sd SET sd.szGeofencingDefault = ct.szDefaultValue
    FROM #storeData sd CROSS JOIN SAM_SM_ConfigTemplateItem ct WITH(NOLOCK)
    WHERE ct.szConfigTemplateId = 'com.sam.geofencing' AND ct.szConfigItemTypeId = 'CUS'

    -- ToggleAI: CUS, CC, Default (both FTO and MD)
    UPDATE sd SET sd.szToggleAICust = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.toggleai' AND ci.szConfigItemTypeId = 'CUS' AND ci.szConfigItemTypeValue = sd.szCustId

    UPDATE sd SET sd.szToggleAICC = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.toggleai' AND ci.szConfigItemTypeId = 'CC' AND ci.szConfigItemTypeValue = sd.szCategory_1

    UPDATE sd SET sd.szToggleAIDefault = ct.szDefaultValue
    FROM #storeData sd CROSS JOIN SAM_SM_ConfigTemplateItem ct WITH(NOLOCK)
    WHERE ct.szConfigTemplateId = 'com.sam.toggleai' AND ct.szConfigItemTypeId = 'CUS'

    PRINT 'Step 2f: AI/geofencing/toggleAI configs done'

    -- CustomerMT
    UPDATE sd SET sd.bIsCustomerMT = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.customercategorymt' AND ci.szConfigItemTypeId = 'CC' AND ci.szConfigItemTypeValue = sd.szCategory_1
    WHERE sd.bIsCustomerMT = '0'

    -- DepoFS fallback for bIsCustomerMT (when ccMT is null)
    UPDATE sd SET sd.bIsCustomerMT = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.depofs' AND ci.szConfigItemTypeId = 'CC' AND ci.szConfigItemTypeValue = sd.szCategory_6
    WHERE sd.bIsCustomerMT = '0'

    -- DepoFS default fallback for MD
    UPDATE sd SET sd.bIsCustomerMT = ct.szDefaultValue
    FROM #storeData sd CROSS JOIN SAM_SM_ConfigTemplateItem ct WITH(NOLOCK)
    WHERE ct.szConfigTemplateId = 'com.sam.depofs' AND ct.szConfigItemTypeId = 'CC'
      AND sd.bIsCustomerMT = '0' AND LEFT(sd.szRouteId, 2) = 'MD'

    -- Popup info
    UPDATE sd SET sd.bShowPopupInformation = ISNULL(ci.szValue, ct.szDefaultValue)
    FROM #storeData sd
    LEFT JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.visitpopupinformation' AND ci.szConfigItemTypeId = 'CC' AND ci.szConfigItemTypeValue = sd.szCategory_1
    CROSS JOIN SAM_SM_ConfigTemplateItem ct WITH(NOLOCK)
    WHERE ct.szConfigTemplateId = 'com.sam.visitpopupinformation' AND ct.szConfigItemTypeId = 'CC'
      AND LEFT(sd.szRouteId, 2) != 'MD'

    -- Popup message
    UPDATE sd SET sd.szMessagePopupInformation = fl.szDescription
    FROM #storeData sd CROSS JOIN AVO_WEB_GEN_FlexTab fl WITH(NOLOCK)
    WHERE fl.szFlexTabId = 'Message Visit Popup Information' AND LEFT(sd.szRouteId, 2) != 'MD'

    -- CekStock
    UPDATE sd SET sd.bAutoOrderWithStock = ISNULL(ci.szValue, ct.szDefaultValue)
    FROM #storeData sd
    LEFT JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.hidevisitmenucekstok' AND ci.szConfigItemTypeId = 'CC' AND ci.szConfigItemTypeValue = sd.szCategory_1
    CROSS JOIN SAM_SM_ConfigTemplateItem ct WITH(NOLOCK)
    WHERE ct.szConfigTemplateId = 'com.sam.hidevisitmenucekstok' AND ct.szConfigItemTypeId = 'CC'

    -- Min order SNS
    UPDATE sd SET sd.decMinOrderAmount = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.minorderamountsns' AND ci.szConfigItemTypeId = 'CC' AND ci.szConfigItemTypeValue = sd.szCategory_2
    WHERE LEFT(sd.szRouteId, 2) != 'MD' AND sd.szCustomerType != 'survey'

    -- GTP Min Order
    UPDATE sd SET sd.decMinimumOrderGTP = gtp.szItemValue
    FROM #storeData sd CROSS JOIN AVO_WEB_Config gtp WITH(NOLOCK)
    WHERE gtp.szConfigId = 'AVO.SD.MinimumOrder' AND gtp.szConfigTypeValue = 'SOHO'

    -- Order Mission Min Order: DEP > CC (self-ref CASE) > Default
    UPDATE sd SET sd.shOrderMissionMinOrder = ct.szDefaultValue
    FROM #storeData sd CROSS JOIN SAM_SM_ConfigTemplateItem ct WITH(NOLOCK)
    WHERE ct.szConfigTemplateId = 'com.sam.ordermissionminorder' AND ct.szConfigItemTypeId = 'CC'
      AND LEFT(sd.szRouteId, 2) != 'MD'

    UPDATE sd SET sd.shOrderMissionMinOrder = ci.szValue
    FROM #storeData sd
    JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.ordermissionminorder' AND ci.szConfigItemTypeId = 'CC'
        AND ci.szConfigItemTypeValue = CASE
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '01' THEN sd.szCategory_1
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '02' THEN sd.szCategory_2
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '03' THEN sd.szCategory_3
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '04' THEN sd.szCategory_4
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '05' THEN sd.szCategory_5
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '06' THEN sd.szCategory_6
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '07' THEN sd.szCategory_7
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '08' THEN sd.szCategory_8
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '09' THEN sd.szCategory_9
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '10' THEN sd.szCategory_10
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '11' THEN sd.szCategory_11
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '12' THEN sd.szCategory_12
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '13' THEN sd.szCategory_13
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '14' THEN sd.szCategory_14
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '15' THEN sd.szCategory_15
        END
    WHERE LEFT(sd.szRouteId, 2) != 'MD'

    UPDATE sd SET sd.shOrderMissionMinOrder = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.ordermissionminorder' AND ci.szConfigItemTypeId = 'DEP' AND ci.szConfigItemTypeValue = sd.szDepartmentId
    WHERE LEFT(sd.szRouteId, 2) != 'MD'

    -- Order Mission Enable Search: DEP > CC (self-ref CASE) > Default
    UPDATE sd SET sd.bOrderMissionEnableSearch = ct.szDefaultValue
    FROM #storeData sd CROSS JOIN SAM_SM_ConfigTemplateItem ct WITH(NOLOCK)
    WHERE ct.szConfigTemplateId = 'com.sam.ordermissionenablesearch' AND ct.szConfigItemTypeId = 'CC'
      AND LEFT(sd.szRouteId, 2) != 'MD'

    UPDATE sd SET sd.bOrderMissionEnableSearch = ci.szValue
    FROM #storeData sd
    JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.ordermissionenablesearch' AND ci.szConfigItemTypeId = 'CC'
        AND ci.szConfigItemTypeValue = CASE
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '01' THEN sd.szCategory_1
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '02' THEN sd.szCategory_2
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '03' THEN sd.szCategory_3
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '04' THEN sd.szCategory_4
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '05' THEN sd.szCategory_5
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '06' THEN sd.szCategory_6
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '07' THEN sd.szCategory_7
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '08' THEN sd.szCategory_8
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '09' THEN sd.szCategory_9
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '10' THEN sd.szCategory_10
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '11' THEN sd.szCategory_11
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '12' THEN sd.szCategory_12
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '13' THEN sd.szCategory_13
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '14' THEN sd.szCategory_14
            WHEN LEFT(ci.szConfigItemTypeValue, 2) = '15' THEN sd.szCategory_15
        END
    WHERE LEFT(sd.szRouteId, 2) != 'MD'

    UPDATE sd SET sd.bOrderMissionEnableSearch = ci.szValue
    FROM #storeData sd JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.ordermissionenablesearch' AND ci.szConfigItemTypeId = 'DEP' AND ci.szConfigItemTypeValue = sd.szDepartmentId
    WHERE LEFT(sd.szRouteId, 2) != 'MD'

    PRINT 'Step 2f: order mission configs done'

    -------------------------------------------------------------------
    -- STEP 2g: Outer SELECT columns (ArClass, MsIdo, Rangkul, MSS)
    -------------------------------------------------------------------
    UPDATE sd SET
        sd.decCreditLimitArClass = ISNULL(t.decCreditLimitArClass, 0),
        sd.szPaymentTermIdArClass = ISNULL(t.szPaymentTermIdArClass, ''),
        sd.bHasChillerTeam = ISNULL(t.bHasChillerTeam, 0)
    FROM #storeData sd JOIN #dataTOP t ON t.szCustId = sd.szCustId AND t.szSalesId = sd.szSalesId

    UPDATE sd SET sd.bRegisteredMsIdo = 1
    FROM #storeData sd JOIN IDO_Users ido WITH(NOLOCK) ON sd.szCustId = ido.bonset_id AND ido.is_success = 1

    UPDATE sd SET sd.bEnableOrderRangkul = ISNULL(sr.szValue, 0)
    FROM #storeData sd
    JOIN IDO_Users ido WITH(NOLOCK) ON sd.szCustId = ido.bonset_id AND ido.is_success = 1
    JOIN SAM_SM_ConfigInfoItem sr WITH(NOLOCK) ON sr.szConfigTemplateId = 'com.sam.orderangkul' AND sr.szValue = 1
        AND (sr.szConfigItemTypeValue = sd.szTeamId OR sr.szConfigItemTypeValue = sd.szWorkplaceId OR sr.szConfigItemTypeValue = sd.szDepartmentId)

    UPDATE sd SET sd.bDisableOrderSAM = ISNULL(ci.szValue, 0)
    FROM #storeData sd
    JOIN SAM_SM_ConfigInfoItem ci WITH(NOLOCK) ON ci.szConfigTemplateId = 'com.sam.rangkulsalesman' AND ci.szValue = 1
        AND (ci.szConfigItemTypeValue = sd.szDepartmentId OR ci.szConfigItemTypeValue = sd.szWorkplaceId)

    UPDATE sd SET sd.bDisableBarcode = ISNULL(cid.szValue, 0)
    FROM #storeData sd
    JOIN SAM_SM_ConfigInfoItem cid WITH(NOLOCK) ON cid.szConfigTemplateId = 'com.sam.disablebarcodevisit' AND cid.szValue = 1
        AND (cid.szConfigItemTypeValue = sd.szDepartmentId OR cid.szConfigItemTypeValue = sd.szWorkplaceId)
    WHERE sd.szCustomerType != 'survey' AND LEFT(sd.szRouteId, 2) != 'MD'

    UPDATE #storeData SET szCCPrevisit1Value = szCategory_1Desc, szCCPrevisit2Value = szCategory_5Desc

    UPDATE sd SET sd.decMSSAchievement =
        CASE WHEN pre.szValue IS NULL THEN 0
        ELSE CAST(REPLACE(SUBSTRING(pre.szValue, CHARINDEX('(', pre.szValue) + 1,
            CHARINDEX(')', pre.szValue) - CHARINDEX('(', pre.szValue) - 1), '%', '') AS DECIMAL(10,2))
        END
    FROM #storeData sd
    JOIN SAM_SLS_Previsit_Information pre WITH(NOLOCK) ON sd.szSalesId = pre.szSalesId AND sd.szCustId = pre.szCustId AND pre.szTitle = 'MSS SKU Ach'
    WHERE sd.szCustomerType != 'survey' AND LEFT(sd.szRouteId, 2) != 'MD'

    PRINT 'Step 2g done: outer columns'

    -------------------------------------------------------------------
    -- STEP 3a: Trivial sub-queries
    -------------------------------------------------------------------

    -- #3 Chiller mapping: per customer → List<string> szChillerId
    SELECT szCustId, STRING_AGG(szChillerId, ',') AS szChillerIds
    INTO #chillerMapping
    FROM (SELECT DISTINCT szCustId, szChillerId FROM SAM_ASM_Chiller WITH(NOLOCK)
          WHERE szCustId IN (SELECT szCustId FROM #routeCustomers)) x
    GROUP BY szCustId
    CREATE INDEX IX_cm ON #chillerMapping (szCustId)

    -- #10 Previsit target: per customer → [{decActual, decTarget, shItemId, szName}]
    SELECT szCustId, shItemId, szItemDesc, decTarget, decActual
    INTO #previsitTarget
    FROM SAM_SD_PrevisitTarget WITH(NOLOCK)
    WHERE szCustId IN (SELECT szCustId FROM #routeCustomers)
    CREATE INDEX IX_pt ON #previsitTarget (szCustId)

    -- #13 Customer active barkul: per customer → bool
    SELECT DISTINCT szCustId
    INTO #customerActiveBarkul
    FROM SAM_AR_CustomerActiveBarkul WITH(NOLOCK)
    WHERE szCustId IN (SELECT szCustId FROM #routeCustomers)
    CREATE INDEX IX_cab ON #customerActiveBarkul (szCustId)

    -- #14 Customer notes: STUB — SP returns empty string (all logic commented out)
    -- C# builds List<string> from (dtmCreated, szNotes) → always ["", ""]
    -- Hardcoded in final SELECT as JSON_QUERY('["",""]')

    -- #6 Activity question ID: per SALESMAN (not per customer)
    SELECT s.szSalesId,
           (SELECT TOP 1 q.szQuestionId
            FROM AVO_SAM_ActivityQuestionItemSales q WITH(NOLOCK)
            WHERE q.szValueId IN (s.szSalesId, r.szRoleId)
            ORDER BY q.szQuestionId ASC) AS szActivityQuestionId
    INTO #activityQuestion
    FROM (SELECT DISTINCT szSalesId FROM #routeCustomers) s
    LEFT JOIN AVO_SAM_SalesRoleMapping r WITH(NOLOCK) ON r.szSalesId = s.szSalesId
    CREATE INDEX IX_aq ON #activityQuestion (szSalesId)

    PRINT 'Step 3a done: trivial sub-queries'

    -------------------------------------------------------------------
    -- STEP 3b: Simple sub-queries
    -------------------------------------------------------------------

    -- Green outlet status per salesman (needed for categoryOrder/categoryProductOrder branching)
    SELECT DISTINCT b.szEmployeeId AS szSalesId,
           CASE WHEN a.szValue IS NOT NULL THEN 1 ELSE 0 END AS bGreenOutlet
    INTO #greenOutlet
    FROM (SELECT DISTINCT szSalesId FROM #routeCustomers) rc
    JOIN BOS_PI_Employee b WITH(NOLOCK) ON b.szEmployeeId = rc.szSalesId
    LEFT JOIN SAM_SM_ConfigInfoItem a WITH(NOLOCK)
        ON a.szConfigTemplateId = 'com.sam.enablegreenoutlet'
        AND a.szConfigItemTypeValue = b.szTeamId AND a.szConfigItemTypeId = 'TEAM'
    CREATE INDEX IX_go ON #greenOutlet (szSalesId)

    -- #1 Category order: per SALESMAN → List<string> (GO vs Non-GO branch)
    -- GO salesmen get 'Category Order', non-GO get 'Category Order Non GO'
    SELECT g.szSalesId,
           STRING_AGG(f.szID, ',') AS szCategoryOrderList
    INTO #categoryOrder
    FROM #greenOutlet g
    JOIN AVO_WEB_GEN_FlexTabItem f WITH(NOLOCK)
        ON f.szFlexTabId = CASE WHEN g.bGreenOutlet = 1 THEN 'Category Order' ELSE 'Category Order Non GO' END
    GROUP BY g.szSalesId
    CREATE INDEX IX_co ON #categoryOrder (szSalesId)

    -- #2 Category product order: per SALESMAN → List<string> (same GO/Non-GO branch)
    SELECT g.szSalesId,
           STRING_AGG(f.szID, ',') AS szCategoryProductOrderList
    INTO #categoryProductOrder
    FROM #greenOutlet g
    JOIN AVO_WEB_GEN_FlexTabItem f WITH(NOLOCK)
        ON f.szFlexTabId = CASE WHEN g.bGreenOutlet = 1 THEN 'Category Product Order' ELSE 'Category Product Order Non GO' END
    GROUP BY g.szSalesId
    CREATE INDEX IX_cpo ON #categoryProductOrder (szSalesId)

    -- #9 Target activities: per customer + date → List<string> szDescription
    SELECT szCustId, STRING_AGG(szDescription, ',') AS szTargetActivities
    INTO #targetActivities
    FROM (
        SELECT szCustId, szDescription FROM sam_sd_dapItemActivityActual WITH(NOLOCK)
        WHERE szCustId IN (SELECT szCustId FROM #routeCustomers)
          AND dtmRouteDate >= @ProcessDate AND dtmRouteDate < DATEADD(DAY, 1, @ProcessDate)
        UNION
        SELECT DISTINCT szCustId, szDescription FROM SAM_SD_DAPItemSKUTargetActivityActual WITH(NOLOCK)
        WHERE szCustId IN (SELECT szCustId FROM #routeCustomers)
          AND dtmRouteDate >= @ProcessDate AND dtmRouteDate < DATEADD(DAY, 1, @ProcessDate)
    ) x
    GROUP BY szCustId
    CREATE INDEX IX_ta ON #targetActivities (szCustId)

    -- #11 Min qty order: per customer → [{szProductId, decMinQty, bMandatory}]
    SELECT b.szCustId, a.szProductId, a.decQty AS decMinQty, CAST(0 AS bit) AS bMandatory
    INTO #minQtyOrder
    FROM SAM_SM_ConfigMinQtyOrder a WITH(NOLOCK)
    JOIN X_VW_SAM_AR_Customer b WITH(NOLOCK) ON a.szCustCategory1 = b.szCategory_1 AND a.szCustCategory6 = b.szCategory_6
    WHERE b.szCustId IN (SELECT szCustId FROM #routeCustomers)
    CREATE INDEX IX_mqo ON #minQtyOrder (szCustId)

    -- #5 Holidays: pre-load for delivery date calculation (Task 4)
    SELECT w.szWorkplaceId, CAST(c.dtmOverride AS date) AS dtmHoliday
    INTO #holidays
    FROM BOS_GL_Workplace w WITH(NOLOCK)
    JOIN BOS_GEN_CalendarOverride c WITH(NOLOCK) ON w.szCalenderId = c.szCalendarId
    WHERE c.bWorkingDay = 0
      AND c.dtmOverride >= @ProcessDate
      AND c.dtmOverride <= DATEADD(DAY, 60, @ProcessDate)
    CREATE INDEX IX_hol ON #holidays (szWorkplaceId, dtmHoliday)

    PRINT 'Step 3b done: simple sub-queries'

    -------------------------------------------------------------------
    -- STEP 3c: Medium sub-query — #targetVisitDisplay (per SALESMAN)
    -------------------------------------------------------------------

    -- #12 Target visit display: per salesman → [{szName, szCategory, szType}]
    -- 4 CTEs: employee dept → GF products + Competitor products UNION
    ;WITH dataEmployee AS (
        SELECT szEmployeeId, szDepartmentId FROM BOS_PI_Employee WITH(NOLOCK)
        WHERE szEmployeeId IN (SELECT DISTINCT szSalesId FROM #routeCustomers)
        UNION
        SELECT szEmployeeId, szDepartmentId FROM AVO_HR_Employee WITH(NOLOCK)
        WHERE szEmployeeId IN (SELECT DISTINCT szSalesId FROM #routeCustomers)
    ), dataGF AS (
        SELECT e.szEmployeeId AS szSalesId,
               ISNULL(d.szCategoryId, '') AS szCategory,
               'Garuda Food' AS szType,
               c.szName
        FROM SAM_SD_VisibilityTarget a WITH(NOLOCK)
        JOIN dataEmployee e ON a.szDepartmentId = e.szDepartmentId
        JOIN BOS_INV_Product c WITH(NOLOCK) ON a.szProductId = c.szProductId
        LEFT JOIN AVO_SLS_SpaceShareCategory d WITH(NOLOCK) ON c.szProductId = d.szProductId
    ), dataComp AS (
        SELECT e.szEmployeeId AS szSalesId,
               ISNULL(d.szCategoryId, '') AS szCategory,
               'Competitor' AS szType,
               c.szDescription AS szName
        FROM SAM_SD_VisibilityTarget a WITH(NOLOCK)
        JOIN dataEmployee e ON a.szDepartmentId = e.szDepartmentId
        JOIN SAM_INV_ProductCompetitor c WITH(NOLOCK) ON a.szProductId = c.szProductId
        LEFT JOIN AVO_SLS_SpaceShareCategory d WITH(NOLOCK) ON c.szProductId = d.szProductId
    )
    SELECT szSalesId, szCategory, szType, szName
    INTO #targetVisitDisplay
    FROM (SELECT * FROM dataGF UNION SELECT * FROM dataComp) x
    CREATE INDEX IX_tvd ON #targetVisitDisplay (szSalesId)

    PRINT 'Step 3c done: #targetVisitDisplay'

    -------------------------------------------------------------------
    -- STEP 4a: Per-workplace delivery date config (BOS_SM_ConfigInfoItem)
    -- NOTE: This uses BOS_SM_ tables (BOSnet config), not SAM_SM_ tables
    -- 4th key column = szConfigItemId (the config "name" within the template)
    -------------------------------------------------------------------
    SELECT
        wp.szWorkplaceId,
        CASE WHEN UPPER(COALESCE(cfgStatus.szValue, 'N')) IN ('Y','YES','TRUE','1') THEN 1 ELSE 0 END AS bStatusDelivery,
        CAST(COALESCE(cfgCat.szValue, '1') AS int) AS iCustomerCategory,
        CAST(COALESCE(cfgExpired.szValue, '7') AS int) AS iExpiredSO,
        CAST(COALESCE(cfgAddDays.szValue, '0') AS int) AS iAddDays
    INTO #deliveryConfig
    FROM (SELECT szWorkplaceId FROM #storeData GROUP BY szWorkplaceId) wp
    LEFT JOIN BOS_SM_ConfigInfoItem cfgStatus
        ON cfgStatus.szConfigTemplateId = 'SNS.DeliveryDatePlan' AND cfgStatus.szConfigItemTypeId = 'WOR'
        AND cfgStatus.szConfigItemTypeValue = wp.szWorkplaceId AND cfgStatus.szConfigItemId = 'Status Delivery Date Plan'
    LEFT JOIN BOS_SM_ConfigInfoItem cfgCat
        ON cfgCat.szConfigTemplateId = 'SNS.DeliveryDatePlan' AND cfgCat.szConfigItemTypeId = 'WOR'
        AND cfgCat.szConfigItemTypeValue = wp.szWorkplaceId AND cfgCat.szConfigItemId = 'Customer Category for Delivery Date'
    LEFT JOIN BOS_SM_ConfigInfoItem cfgExpired
        ON cfgExpired.szConfigTemplateId = 'com.kontinum.bos.sd.FSo' AND cfgExpired.szConfigItemTypeId = 'WOR'
        AND cfgExpired.szConfigItemTypeValue = wp.szWorkplaceId AND cfgExpired.szConfigItemId = 'Add Day for Expired Date'
    LEFT JOIN BOS_SM_ConfigInfoItem cfgAddDays
        ON cfgAddDays.szConfigTemplateId = 'com.kontinum.bos.sd.FSo' AND cfgAddDays.szConfigItemTypeId = 'WOR'
        AND cfgAddDays.szConfigItemTypeValue = wp.szWorkplaceId AND cfgAddDays.szConfigItemId = 'Count of Next Delivery Date'

    CREATE INDEX IX_dc ON #deliveryConfig (szWorkplaceId)
    PRINT 'Step 4a done: delivery config'

    -------------------------------------------------------------------
    -- STEP 4b: Per-customer delivery plan (cascading: customer → category → default)
    -- C# flow: p_GetDeliveryDatePlan → cascading config → nextDelivery count
    -------------------------------------------------------------------
    SELECT sd.szCustId, sd.szWorkplaceId,
        CASE
            WHEN dc.bStatusDelivery = 1 AND cust.szCustId IS NOT NULL
                THEN cust.iCountOfNextDeliveryDate
            WHEN dc.bStatusDelivery = 1 AND cat.szCategoryId IS NOT NULL
                THEN cat.iCountOfNextDeliveryDate
            ELSE dc.iAddDays
        END AS iNextDelivery,
        CASE
            WHEN dc.bStatusDelivery = 1 AND cust.szCustId IS NOT NULL THEN cust.szType
            WHEN dc.bStatusDelivery = 1 AND cat.szCategoryId IS NOT NULL THEN cat.szType
            ELSE 'SO'
        END AS szTypeDeliveryPlan,
        CASE WHEN dc.bStatusDelivery = 1 THEN dc.iExpiredSO ELSE NULL END AS iExpiredSO,
        -- MT special case: custom plan (different from workplace default) + MT → skip holiday shift
        CASE WHEN sd.bIsCustomerMT = '1' AND dc.bStatusDelivery = 1
             AND (cust.szCustId IS NOT NULL OR cat.szCategoryId IS NOT NULL)
             AND COALESCE(cust.iCountOfNextDeliveryDate, cat.iCountOfNextDeliveryDate) != dc.iAddDays
             THEN 1 ELSE 0 END AS bMTCustomPlan
    INTO #deliveryPlan
    FROM (
        SELECT szCustId, szWorkplaceId, bIsCustomerMT,
            szCategory_1, szCategory_2, szCategory_3, szCategory_4, szCategory_5,
            szCategory_6, szCategory_7, szCategory_8, szCategory_9, szCategory_10,
            szCategory_11, szCategory_12, szCategory_13, szCategory_14, szCategory_15,
            ROW_NUMBER() OVER (PARTITION BY szCustId, szWorkplaceId ORDER BY szCustId) AS rn
        FROM #storeData
    ) sd
    JOIN #deliveryConfig dc ON dc.szWorkplaceId = sd.szWorkplaceId
    LEFT JOIN SNS_DeliveryDatePlan_ItemCustomer cust
        ON cust.szCustId = sd.szCustId AND cust.szWorkplaceId = sd.szWorkplaceId AND dc.bStatusDelivery = 1
    LEFT JOIN SNS_DeliveryDatePlan_ItemCustomerCategory cat
        ON cat.szWorkplaceId = sd.szWorkplaceId AND dc.bStatusDelivery = 1 AND cust.szCustId IS NULL
        AND cat.szCategoryId = CASE dc.iCustomerCategory
            WHEN 1 THEN sd.szCategory_1 WHEN 2 THEN sd.szCategory_2 WHEN 3 THEN sd.szCategory_3
            WHEN 4 THEN sd.szCategory_4 WHEN 5 THEN sd.szCategory_5 WHEN 6 THEN sd.szCategory_6
            WHEN 7 THEN sd.szCategory_7 WHEN 8 THEN sd.szCategory_8 WHEN 9 THEN sd.szCategory_9
            WHEN 10 THEN sd.szCategory_10 WHEN 11 THEN sd.szCategory_11 WHEN 12 THEN sd.szCategory_12
            WHEN 13 THEN sd.szCategory_13 WHEN 14 THEN sd.szCategory_14 WHEN 15 THEN sd.szCategory_15
        END
    WHERE sd.rn = 1

    CREATE INDEX IX_dp ON #deliveryPlan (szCustId, szWorkplaceId)
    PRINT 'Step 4b done: delivery plan per customer'

    -------------------------------------------------------------------
    -- STEP 4c: Compute final delivery date via tally table
    -- C# two-pass algorithm (skip Sundays → skip holidays) simplifies to:
    -- "Find the Nth working day from @ProcessDate"
    -- where working = not Sunday AND not holiday (unless MT with custom plan → Sunday-only)
    -------------------------------------------------------------------
    ;WITH tally AS (
        SELECT TOP 61 ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS n
        FROM sys.objects
    ), workingDays AS (
        SELECT dp.szCustId, dp.szWorkplaceId,
            DATEADD(DAY, t.n, @ProcessDate) AS dtmCandidate,
            ROW_NUMBER() OVER (PARTITION BY dp.szCustId, dp.szWorkplaceId ORDER BY t.n) - 1 AS rn
        FROM #deliveryPlan dp
        CROSS JOIN tally t
        LEFT JOIN #holidays h ON h.szWorkplaceId = dp.szWorkplaceId
            AND h.dtmHoliday = CAST(DATEADD(DAY, t.n, @ProcessDate) AS date)
        WHERE DATEPART(dw, DATEADD(DAY, t.n, @ProcessDate)) != 1  -- skip Sunday (DATEFIRST=7: Sun=1)
          AND (dp.bMTCustomPlan = 1 OR h.dtmHoliday IS NULL)      -- skip holidays unless MT-custom
    )
    UPDATE sd SET
        sd.dtmDelivery = CONVERT(varchar(10), wd.dtmCandidate, 23),
        sd.dtmExpiredSO = CASE WHEN dp.iExpiredSO IS NOT NULL
            THEN CONVERT(varchar(10), DATEADD(DAY, dp.iExpiredSO, @ProcessDate), 23) ELSE '' END,
        sd.szTypeDeliveryPlan = dp.szTypeDeliveryPlan
    FROM #storeData sd
    JOIN #deliveryPlan dp ON dp.szCustId = sd.szCustId AND dp.szWorkplaceId = sd.szWorkplaceId
    JOIN workingDays wd ON wd.szCustId = dp.szCustId AND wd.szWorkplaceId = dp.szWorkplaceId
        AND wd.rn = dp.iNextDelivery

    PRINT 'Step 4c done: delivery dates computed'

    -------------------------------------------------------------------
    -- STEP 4d: OtherInfo — SAM_API_GetDataPrevisitInformation (6 branches → 2 for batch)
    -- C# groups rows by (szType, szTypeColor) → nested JSON [{szType, szColor, lsItems}]
    -- JSON nesting deferred to final SELECT (Task 6)
    -------------------------------------------------------------------

    -- Previsit info: Green Outlet salesmen get all types (minus 3 excluded); non-GO get Sales Performance only
    SELECT sd.szSalesId, sd.szCustId, p.shOrder, p.szType, p.szTypeColor, p.shOrderItem,
           p.szTitle, p.szValue, p.szColor
    INTO #otherInfo
    FROM #storeData sd
    JOIN #greenOutlet go ON go.szSalesId = sd.szSalesId
    JOIN SAM_SLS_Previsit_Information p WITH(NOLOCK) ON p.szSalesId = sd.szSalesId AND p.szCustId = sd.szCustId
    WHERE (go.bGreenOutlet = 1
           AND p.szTitle NOT IN ('Actual vs Target Bulanan', 'Sisa Target Bulan Ini', 'MSS Active/Standard'))
       OR (go.bGreenOutlet = 0 AND p.szType = 'Sales Performance')

    -- Target DAP: only for Operational + Green Outlet salesmen
    -- Date logic matches SP: tomorrow, or day-after-tomorrow if tomorrow is Sunday
    DECLARE @dtmDAP date = CASE
        WHEN DATEPART(dw, DATEADD(DAY, 1, @ProcessDate)) = 1
        THEN DATEADD(DAY, 2, @ProcessDate)
        ELSE DATEADD(DAY, 1, @ProcessDate)
    END

    INSERT INTO #otherInfo (szSalesId, szCustId, shOrder, szType, szTypeColor, shOrderItem, szTitle, szValue, szColor)
    SELECT d.szSalesId, d.szCustId, 1, 'Sales Performance', '', 2,
           'Target DAP', dbo.FormatShortIndo(d.decTotalSalesPlan), ''
    FROM SAM_SD_DAPItem d WITH(NOLOCK)
    JOIN (SELECT szSalesId, szCustId FROM #storeData GROUP BY szSalesId, szCustId) sd
        ON d.szSalesId = sd.szSalesId AND d.szCustId = sd.szCustId
    JOIN #greenOutlet go ON go.szSalesId = sd.szSalesId AND go.bGreenOutlet = 1
    JOIN AVO_SLS_EmployeeOrg eo WITH(NOLOCK) ON eo.szEmployeeId = sd.szSalesId AND eo.szPositionLevelName = 'Operational'
    WHERE d.dtmRouteDate >= @dtmDAP AND d.dtmRouteDate < DATEADD(DAY, 1, @dtmDAP)

    CREATE INDEX IX_oi_cust ON #otherInfo (szCustId, szSalesId)

    PRINT 'Step 4d done: #otherInfo'

    -------------------------------------------------------------------
    -- STEP 5: Priority config chains — compute final values from raw config columns
    -- Raw values already in #storeData from Step 2f config UPDATEs
    -- C# logic: RouteDetail_m.cs lines 231-341
    -------------------------------------------------------------------

    -- 1. szConfigBarcode: CUS > CC > SLS > WOR > Default, with guard
    UPDATE #storeData SET szConfigBarcode =
        CASE WHEN bDisableBarcode = '1' OR bUpdateCoordinate = 1 THEN ''
        ELSE COALESCE(NULLIF(szBarcodeCust, ''), NULLIF(szBarcodeCC, ''), NULLIF(szBarcodeSales, ''), NULLIF(szBarcodeWor, ''), szBarcodeDefault)
        END

    -- 2-5: Three-level chains (CUS > CC > Default), stored as string for JSON
    -- Note: bEnableFeatureAI etc. are written as bool (== "1") in Firestore
    -- We store the raw COALESCE value; the final SELECT converts to bool

    -- ManualProductAI: FIX C# bug on line 296 — original checks szFeatureAICC instead of szManualProductAICC
    -- Plan decision: fix in SP (use correct condition szManualProductAICC)

    PRINT 'Step 5 done: priority config chains (computed inline in final SELECT)'

    -------------------------------------------------------------------
    -- STEP 6: Final SELECT — JSON assembly + metadata output
    -- C# source: RouteDetail_m.cs:505-575 (routeDetailData dictionary)
    -- Nested objects: customer, targetSales, ikatTarget, orderMission
    -- Array fields: lsCategoryOrder, lsProductCategoryOrder, lsChillerId,
    --   lsTargetVisitDisplay, targetActivities, previsitTarget, lsMinQtyOrder,
    --   lsOtherInfo, lsStoreKeywordSearch, szNotes (in customer)
    -------------------------------------------------------------------
    SELECT
        NEWID()                                                               AS MessageID,
        @ConfigCollectionName                                                 AS CollectionName,
        CONVERT(nvarchar(200), CONCAT_WS('/', 'salesman', sd.szSalesId,
            'route', sd.szRouteId, 'store'))                                  AS CollectionPath,
        CONVERT(nvarchar(100), sd.szCustId)                                   AS DocID,
        CONVERT(varchar(30), sd.szSalesId)                                    AS SalesID,
        CAST(NULL AS nvarchar(max))                                           AS Metadata,
        (
            SELECT
                -- Delivery date
                sd.dtmDelivery                                                AS dtmOrderDelivery,
                sd.dtmExpiredSO                                               AS dtmExpiredSO,
                sd.szTypeDeliveryPlan                                         AS szTypeDelivery,
                -- Static booleans
                CAST(0 AS bit)                                                AS bFinish,
                CAST(0 AS bit)                                                AS bPostpone,
                CAST(0 AS bit)                                                AS bSuccess,
                CAST(1 AS bit)                                                AS bInRoute,
                -- Config booleans from #storeData
                CASE WHEN sd.bEnableOrderRangkul = '1' THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END AS bEnableOrderRangkul,
                CASE WHEN sd.bDisableOrderSAM = '1' THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END AS bDisableOrderSAM,
                CASE WHEN sd.bIsCustomerMT = '1' THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END AS bIsCustomerMT,
                sd.bRegisteredMsIdo                                           AS bRegisteredMsIdo,
                CAST(0 AS bit)                                                AS bChillerFinished,
                -- Customer nested object
                JSON_QUERY((
                    SELECT
                        sd.szCustId                                           AS szCustId,
                        sd.szName                                             AS szName,
                        sd.CustszEmail                                        AS szEmailAddress,
                        sd.CustszContactPerson                                AS custszContactPerson,
                        CONVERT(varchar(10), @ProcessDate, 23)                AS dtmBirthday,
                        ISNULL(sd.szNoKTP, '')                                AS szIDNumber,
                        ISNULL(sd.szNPWP, '')                                 AS szNPWP,
                        sd.szRT                                               AS szRT,
                        sd.szRW                                               AS szRW,
                        sd.TaxszAddress_1                                     AS szTaxAddress1,
                        sd.TaxszAddress_2                                     AS szTaxAddress2,
                        sd.TaxszDistrict                                      AS szTaxDistrict,
                        sd.szNamaKTP                                          AS szNamaKTP,
                        sd.CustszAddress_1                                    AS szAddress,
                        sd.CustszAddress_2                                    AS szAddress2,
                        sd.CustszDistrict                                     AS szDistrict,
                        sd.CustszCity                                         AS szCity,
                        sd.CustszZipCode                                      AS szZipCode,
                        sd.CustszState                                        AS szState,
                        sd.CustszCountry                                      AS szCountry,
                        JSON_QUERY('["",""]')                                 AS szNotes,
                        sd.CustszMobileNo                                     AS szPhoneNo,
                        sd.CustszPhoneNo_1                                    AS szCustszPhoneNo1,
                        sd.CustszPhoneNo_2                                    AS szCustszPhoneNo2,
                        -- MT caption swap (C# lines 373-380)
                        'Type Outlet (CC1)'                                   AS szCatInfoCaption1,
                        sd.szCategory_1Desc                                   AS szCatInfoValue1,
                        CASE WHEN sd.bIsCustomerMT = '1' THEN 'Customer Segment (CC5)' ELSE 'Sub Type Outlet (CC2)' END AS szCatInfoCaption2,
                        CASE WHEN sd.bIsCustomerMT = '1' THEN sd.szCategory_5Desc ELSE sd.szCategory_2Desc END AS szCatInfoValue2,
                        CASE WHEN sd.bIsCustomerMT = '1' THEN 'Tipe Produk Dijual (CC6)' ELSE 'Customer Segment (CC5)' END AS szCatInfoCaption3,
                        CASE WHEN sd.bIsCustomerMT = '1' THEN sd.szCategory_6Desc ELSE sd.szCategory_5Desc END AS szCatInfoValue3,
                        CASE WHEN sd.bIsCustomerMT = '1' THEN 'Harga (CC8)' ELSE 'Tipe Harga (CC9)' END AS szCatInfoCaption4,
                        CASE WHEN sd.bIsCustomerMT = '1' THEN sd.szCategory_8Desc ELSE sd.szCategory_9Desc END AS szCatInfoValue4,
                        'Credit Limit'                                        AS szCatInfoCaption5,
                        CONVERT(varchar(30), CASE WHEN sd.decCreditLimitArClass = 0 THEN sd.decCreditLimit ELSE sd.decCreditLimitArClass END, 1) AS szCatInfoValue5,
                        'Tipe Produk Dijual (CC6)'                            AS szCatInfoCaption6,
                        sd.szCategory_6Desc                                   AS szCatInfoValue6,
                        sd.szCategory_5Desc                                   AS szStoreCategory,
                        sd.szCategory_1 AS szCusCategory_1, sd.szCategory_2 AS szCusCategory_2,
                        sd.szCategory_3 AS szCusCategory_3, sd.szCategory_4 AS szCusCategory_4,
                        sd.szCategory_5 AS szCusCategory_5, sd.szCategory_6 AS szCusCategory_6,
                        sd.szCategory_7 AS szCusCategory_7, sd.szCategory_8 AS szCusCategory_8,
                        sd.szCategory_9 AS szCusCategory_9, sd.szCategory_10 AS szCusCategory_10,
                        sd.szCategory_11 AS szCusCategory_11, sd.szCategory_12 AS szCusCategory_12,
                        sd.szCategory_13 AS szCusCategory_13, sd.szCategory_14 AS szCusCategory_14,
                        sd.szCategory_15 AS szCusCategory_15,
                        '' AS szPriceId, '' AS szPromoPriceId,
                        sd.szDlvWorkplaceId                                   AS szDlvWorkplaceId,
                        '' AS szCustCategoryPriceId_1_J, '' AS szCustCategoryPriceId_2_J,
                        '' AS szCustCategoryPriceId_3_J, '' AS szCustCategoryPriceId_4_J,
                        '' AS szCustCategoryPriceId_5_J, '' AS szCustCategoryPriceId_6_J,
                        '' AS szCustCategoryPriceId_7_J, '' AS szCustCategoryPriceId_8_J,
                        '' AS szCustCategoryPriceId_9_J, '' AS szCustCategoryPriceId_10_J,
                        '' AS szCustCategoryPriceId_11_J, '' AS szCustCategoryPriceId_12_J,
                        '' AS szCustCategoryPriceId_13_J, '' AS szCustCategoryPriceId_14_J,
                        '' AS szCustCategoryPriceId_15_J,
                        '' AS szCustCategoryPromoPriceId_1_J, '' AS szCustCategoryPromoPriceId_2_J,
                        '' AS szCustCategoryPromoPriceId_3_J, '' AS szCustCategoryPromoPriceId_4_J,
                        '' AS szCustCategoryPromoPriceId_5_J, '' AS szCustCategoryPromoPriceId_6_J,
                        '' AS szCustCategoryPromoPriceId_7_J, '' AS szCustCategoryPromoPriceId_8_J,
                        '' AS szCustCategoryPromoPriceId_9_J, '' AS szCustCategoryPromoPriceId_10_J,
                        '' AS szCustCategoryPromoPriceId_11_J, '' AS szCustCategoryPromoPriceId_12_J,
                        '' AS szCustCategoryPromoPriceId_13_J, '' AS szCustCategoryPromoPriceId_14_J,
                        '' AS szCustCategoryPromoPriceId_15_J,
                        '' AS szCustCategoryPriceOrderId_1_J, '' AS szCustCategoryPriceOrderId_2_J,
                        '' AS szCustCategoryPriceOrderId_3_J, '' AS szCustCategoryPriceOrderId_4_J,
                        '' AS szCustCategoryPriceOrderId_5_J, '' AS szCustCategoryPriceOrderId_6_J,
                        '' AS szCustCategoryPriceOrderId_7_J, '' AS szCustCategoryPriceOrderId_8_J,
                        '' AS szCustCategoryPriceOrderId_9_J, '' AS szCustCategoryPriceOrderId_10_J,
                        '' AS szCustCategoryPriceOrderId_11_J, '' AS szCustCategoryPriceOrderId_12_J,
                        '' AS szCustCategoryPriceOrderId_13_J, '' AS szCustCategoryPriceOrderId_14_J,
                        '' AS szCustCategoryPriceOrderId_15_J,
                        '' AS szCustCategoryPromoPriceOrderId_1_J, '' AS szCustCategoryPromoPriceOrderId_2_J,
                        '' AS szCustCategoryPromoPriceOrderId_3_J, '' AS szCustCategoryPromoPriceOrderId_4_J,
                        '' AS szCustCategoryPromoPriceOrderId_5_J, '' AS szCustCategoryPromoPriceOrderId_6_J,
                        '' AS szCustCategoryPromoPriceOrderId_7_J, '' AS szCustCategoryPromoPriceOrderId_8_J,
                        '' AS szCustCategoryPromoPriceOrderId_9_J, '' AS szCustCategoryPromoPriceOrderId_10_J,
                        '' AS szCustCategoryPromoPriceOrderId_11_J, '' AS szCustCategoryPromoPriceOrderId_12_J,
                        '' AS szCustCategoryPromoPriceOrderId_13_J, '' AS szCustCategoryPromoPriceOrderId_14_J,
                        '' AS szCustCategoryPromoPriceOrderId_15_J
                    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
                ))                                                            AS customer,
                -- Credit limit (ArClass override)
                CASE WHEN sd.decCreditLimitArClass = 0 THEN sd.decCreditLimit ELSE sd.decCreditLimitArClass END AS decCreditLimit,
                -- Static zeros/empty
                0                                                             AS decJourneySpendTime,
                0                                                             AS decLastOrder,
                0                                                             AS decTargetOrder,
                0                                                             AS decVisitSpendTime,
                ''                                                            AS dtmEndVisit,
                ''                                                            AS dtmStartVisit,
                -- Array fields: category orders (per salesman)
                JSON_QUERY(CASE WHEN co.szCategoryProductOrderList IS NOT NULL
                    THEN '["' + REPLACE(co.szCategoryProductOrderList, ',', '","') + '"]'
                    ELSE '[]' END)                                            AS lsProductCategoryOrder,
                JSON_QUERY(CASE WHEN cat.szCategoryOrderList IS NOT NULL
                    THEN '["' + REPLACE(cat.szCategoryOrderList, ',', '","') + '"]'
                    ELSE '[]' END)                                            AS lsCategoryOrder,
                -- Keyword search: ["", word1, word2, ...]
                JSON_QUERY('["' + REPLACE(sd.szName, ' ', '","') + '"]')      AS lsStoreKeywordSearch,
                JSON_QUERY('[]')                                              AS lsTargetPemajangan,
                -- Target visit display (per salesman → array of objects)
                JSON_QUERY(COALESCE((
                    SELECT szName, szCategory, szType
                    FROM #targetVisitDisplay tvd
                    WHERE tvd.szSalesId = sd.szSalesId
                    FOR JSON PATH
                ), '[]'))                                                     AS lsTargetVisitDisplay,
                -- Chiller IDs (per customer)
                JSON_QUERY(CASE WHEN cm.szChillerIds IS NOT NULL
                    THEN '["' + REPLACE(cm.szChillerIds, ',', '","') + '"]'
                    ELSE '[]' END)                                            AS lsChillerId,
                -- Scalars
                0                                                             AS shOrderFinish,
                CAST(sd.intPrintedMaxPaymentDay AS int)                       AS shTermOfPayment,
                CASE WHEN sd.szPaymentTermIdArClass = '' THEN sd.szPaymentTermId ELSE sd.szPaymentTermIdArClass END AS szPaymentTermId,
                0                                                             AS shVisitDay,
                sd.szBarcodeId                                                AS szBarcode,
                ''                                                            AS szCurLatitude,
                ''                                                            AS szCurLongitude,
                sd.szLatitude                                                 AS szLatitude,
                sd.szLongitude                                                AS szLongitude,
                ''                                                            AS szReasonId,
                sd.szCustId                                                   AS szStoreId,
                ISNULL(aq.szActivityQuestionId, '')                           AS szActivityQuestionId,
                sd.szActivityStatusOrder                                      AS szActivityStatus,
                CASE WHEN sd.bHasChillerTeam = 1 THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END AS bIsChiller,
                CAST(sd.decMinOrderAmount AS float)                           AS decMinimumOrder,
                CAST(sd.decMinimumOrderGTP AS float)                          AS decMinimumOrderGTP,
                CASE WHEN sd.bAllowToCredit = 1 THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END AS bAllowToCredit,
                CONVERT(varchar(10), @ProcessDate, 23)                        AS dtmCreatedAt,
                CAST(sd.shItemNumber AS int)                                  AS shItemNumber,
                sd.szSalesId                                                  AS szSalesId,
                -- Target activities (per customer)
                JSON_QUERY(CASE WHEN ta.szTargetActivities IS NOT NULL
                    THEN '["' + REPLACE(ta.szTargetActivities, ',', '","') + '"]'
                    ELSE '[]' END)                                            AS targetActivities,
                -- Previsit target (per customer → array of objects)
                JSON_QUERY(COALESCE((
                    SELECT CAST(pt.decActual AS float) AS decActual,
                           CAST(pt.decTarget AS float) AS decTarget,
                           CAST(pt.shItemId AS int) AS shItemId,
                           pt.szItemDesc AS szName
                    FROM #previsitTarget pt
                    WHERE pt.szCustId = sd.szCustId
                    FOR JSON PATH
                ), '[]'))                                                     AS previsitTarget,
                -- Min qty order (per customer → array of objects)
                JSON_QUERY(COALESCE((
                    SELECT mqo.szProductId, CAST(mqo.decMinQty AS float) AS decMinQty,
                           mqo.bMandatory
                    FROM #minQtyOrder mqo
                    WHERE mqo.szCustId = sd.szCustId
                    FOR JSON PATH
                ), '[]'))                                                     AS lsMinQtyOrder,
                -- Other info (nested grouped JSON)
                JSON_QUERY(COALESCE((
                    SELECT oi_hdr.szType, oi_hdr.szTypeColor AS szColor,
                        JSON_QUERY((
                            SELECT oi_item.szTitle, oi_item.szColor, oi_item.szValue
                            FROM #otherInfo oi_item
                            WHERE oi_item.szCustId = sd.szCustId AND oi_item.szSalesId = sd.szSalesId
                              AND oi_item.szType = oi_hdr.szType
                            ORDER BY oi_item.shOrderItem
                            FOR JSON PATH
                        )) AS lsItems
                    FROM (SELECT szCustId, szSalesId, szType, szTypeColor, shOrder
                          FROM #otherInfo
                          WHERE szCustId = sd.szCustId AND szSalesId = sd.szSalesId
                          GROUP BY szCustId, szSalesId, szType, szTypeColor, shOrder) oi_hdr
                    ORDER BY oi_hdr.shOrder
                    FOR JSON PATH
                ), '[]'))                                                     AS lsOtherInfo,
                -- Target sales nested object
                JSON_QUERY((
                    SELECT
                        CAST(sd.decTargetDAP AS float)        AS decTargetDAP,
                        CAST(sd.decTotalSalesPlan AS float)   AS decTargetToday,
                        CAST(sd.decTargetRemain AS float)     AS decTargetRemain,
                        CAST(sd.decMonthlyTarget AS float)    AS decTargetMonthly,
                        CAST(sd.decPercentage AS float)       AS decTargetMonthlyPercentage
                    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
                ))                                                            AS targetSales,
                -- Ikat target nested object
                JSON_QUERY((
                    SELECT
                        CAST(sd.decITGActual AS float)        AS decActual,
                        CAST(sd.decITGTarget AS float)        AS decTarget
                    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
                ))                                                            AS ikatTarget,
                -- Priority config chains (Task 5 — computed inline)
                sd.szConfigBarcode                                            AS szConfigBarcode,
                CASE WHEN COALESCE(NULLIF(sd.szFeatureAICust, ''), NULLIF(sd.szFeatureAICC, ''), sd.szFeatureAIDefault) = '1'
                     THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END             AS bEnableFeatureAI,
                -- FIX: C# bug line 296 checks szFeatureAICC → we use correct szManualProductAICC
                CASE WHEN COALESCE(NULLIF(sd.szManualProductAICust, ''), NULLIF(sd.szManualProductAICC, ''), sd.szManualProductAIDefault) = '1'
                     THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END             AS bEnableManualAddProductDisplayMt,
                CASE WHEN COALESCE(NULLIF(sd.szGeofencingCust, ''), NULLIF(sd.szGeofencingCC, ''), sd.szGeofencingDefault) = '1'
                     THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END             AS bGeofencing,
                CASE WHEN COALESCE(NULLIF(sd.szToggleAICust, ''), NULLIF(sd.szToggleAICC, ''), sd.szToggleAIDefault) = '1'
                     THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END             AS bToggleAI,
                -- Popup and stock configs (note: C# inverts == "0" → true)
                CASE WHEN sd.bShowPopupInformation = '0' THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END AS bShowPopupInformation,
                sd.szMessagePopupInformation                                  AS szMessagePopupInformation,
                CASE WHEN sd.bAutoOrderWithStock = '0' THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END AS bAutoOrderWithStock,
                sd.szCCPrevisit1Value                                         AS szCCPrevisit1Value,
                sd.szCCPrevisit2Value                                         AS szCCPrevisit2Value,
                -- Barkul
                CASE WHEN cab.szCustId IS NOT NULL THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END AS bIsCARangkul,
                CAST(sd.decMSSAchievement AS float)                           AS decMSSAchievement,
                sd.szCustomerType                                             AS szCustomerType,
                -- Order mission nested object
                JSON_QUERY((
                    SELECT
                        CAST(sd.shOrderMissionMinOrder AS int)  AS shMinOrder,
                        CASE WHEN sd.bOrderMissionEnableSearch = '1' THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END AS bIsShowSearch
                    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
                ))                                                            AS orderMission,
                DATEADD(DAY, @TTL, CONVERT(datetime, @ProcessDate))           AS dtmExpiration
            FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
        )                                                                     AS Rawdata,
        HASHBYTES('SHA2_256', (
            SELECT sd.szCustId AS szCustId, sd.szSalesId AS szSalesId
            FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
        ))                                                                    AS RawdataHash,
        GETDATE()                                                             AS CreatedAt,
        0                                                                     AS PublishStatus,
        0                                                                     AS RetryCount,
        CAST(NULL AS nvarchar(max))                                           AS ErrorMessage,
        CAST(NULL AS datetime)                                                AS LastPublishAttempt,
        @ScopeType                                                            AS ScopeType,
        0                                                                     AS StatusSync,
        GETDATE()                                                             AS LastAttemptAt
    FROM #storeData sd
    LEFT JOIN #categoryOrder cat ON cat.szSalesId = sd.szSalesId
    LEFT JOIN #categoryProductOrder co ON co.szSalesId = sd.szSalesId
    LEFT JOIN #chillerMapping cm ON cm.szCustId = sd.szCustId
    LEFT JOIN #targetActivities ta ON ta.szCustId = sd.szCustId
    LEFT JOIN #activityQuestion aq ON aq.szSalesId = sd.szSalesId
    LEFT JOIN #customerActiveBarkul cab ON cab.szCustId = sd.szCustId
    OPTION (MAXDOP 8)

    PRINT 'Step 6 done: final SELECT'

END